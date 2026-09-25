//! OAuth 2.1 Authorization-Code + PKCE (S256) provider for the MCP server.
//!
//! Designed for a single-operator setup: the "resource owner password" is the
//! existing MCP shared secret (printed at startup as "[mcp] oauth password: …").
//! A browser form collects that password during the Authorization step, so
//! ChatGPT's OAuth connector can complete the full Authorization-Code + PKCE
//! dance without a separate identity system.
//!
//! Authorization codes stay in-process. Issued access tokens are persisted locally
//! with absolute expiry so an MCP restart does not invalidate an authenticated connector.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// OAuth state + durable access-token store
// ---------------------------------------------------------------------------

struct AuthCodeEntry {
    code_challenge: String,
    redirect_uri: String,
    expiry: Instant,
}

#[derive(Clone, Serialize, Deserialize)]
struct TokenEntry {
    expires_at: u64,
}

struct OauthState {
    codes: HashMap<String, AuthCodeEntry>,
    tokens: HashMap<String, TokenEntry>,
}

const ACCESS_TOKEN_TTL_SECS: u64 = 86_400;
const TOKEN_STORE_VERSION: u8 = 1;
const MAX_TOKEN_STORE_BYTES: u64 = 1024 * 1024;
const MAX_PERSISTED_TOKENS: usize = 256;

#[derive(Serialize, Deserialize)]
struct PersistedTokenStore {
    v: u8,
    server_id: String,
    tokens: HashMap<String, TokenEntry>,
}

#[cfg_attr(test, allow(dead_code))]
struct StoreConfig {
    path: PathBuf,
    server_id: String,
}

static STATE: OnceLock<Mutex<OauthState>> = OnceLock::new();
static STORE_CONFIG: OnceLock<StoreConfig> = OnceLock::new();
static TOKEN_WRITER: Mutex<()> = Mutex::new(());

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before UNIX epoch: {e}"))
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn token_digest(token: &str) -> String {
    sha256_hex(token.as_bytes())
}
fn current_uid() -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|e| format!("reading current uid: {e}"))
}

fn secure_store_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(format!(
                    "OAuth state dir is not a real directory: {}",
                    dir.display()
                ));
            }
            if meta.uid() != current_uid()? {
                return Err(format!(
                    "OAuth state dir is not owned by current user: {}",
                    dir.display()
                ));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| format!("securing OAuth state dir: {e}"))?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(dir)
                .map_err(|e| format!("creating OAuth state dir: {e}"))?;
        }
        Err(e) => return Err(format!("inspecting OAuth state dir: {e}")),
    }
    Ok(())
}

fn validate_store_file(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(format!(
                    "OAuth token store is not a real file: {}",
                    path.display()
                ));
            }
            if meta.uid() != current_uid()? || meta.permissions().mode() & 0o077 != 0 {
                return Err(format!(
                    "unsafe ownership or permissions on OAuth token store: {}",
                    path.display()
                ));
            }
            if meta.len() > MAX_TOKEN_STORE_BYTES {
                return Err(format!(
                    "OAuth token store exceeds {MAX_TOKEN_STORE_BYTES} bytes"
                ));
            }
            Ok(Some(meta))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("inspecting OAuth token store: {e}")),
    }
}
fn load_tokens_from(path: &Path, server_id: &str) -> Result<HashMap<String, TokenEntry>, String> {
    if validate_store_file(path)?.is_none() {
        return Ok(HashMap::new());
    }
    let body = std::fs::read(path).map_err(|e| format!("reading OAuth token store: {e}"))?;
    if body.len() as u64 > MAX_TOKEN_STORE_BYTES {
        return Err(format!(
            "OAuth token store exceeds {MAX_TOKEN_STORE_BYTES} bytes"
        ));
    }
    let mut store: PersistedTokenStore =
        serde_json::from_slice(&body).map_err(|e| format!("parsing OAuth token store: {e}"))?;
    if store.v != TOKEN_STORE_VERSION {
        return Err(format!(
            "unsupported OAuth token store version: {}",
            store.v
        ));
    }
    if store.server_id != server_id {
        return Err("OAuth token store server identity mismatch".to_string());
    }
    if store.tokens.len() > MAX_PERSISTED_TOKENS {
        return Err(format!(
            "OAuth token store has too many entries: {}",
            store.tokens.len()
        ));
    }
    let now = unix_now()?;
    store.tokens.retain(|_, entry| entry.expires_at > now);
    Ok(store.tokens)
}

fn persist_tokens_to(
    path: &Path,
    server_id: &str,
    tokens: &HashMap<String, TokenEntry>,
) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    if tokens.len() > MAX_PERSISTED_TOKENS {
        return Err(format!(
            "refusing to persist more than {MAX_PERSISTED_TOKENS} OAuth tokens"
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "OAuth token store has no parent directory".to_string())?;
    secure_store_dir(parent)?;
    let body = serde_json::to_vec_pretty(&PersistedTokenStore {
        v: TOKEN_STORE_VERSION,
        server_id: server_id.to_string(),
        tokens: tokens.clone(),
    })
    .map_err(|e| format!("serializing OAuth token store: {e}"))?;
    if body.len() as u64 > MAX_TOKEN_STORE_BYTES {
        return Err(format!(
            "serialized OAuth token store exceeds {MAX_TOKEN_STORE_BYTES} bytes"
        ));
    }
    let tmp = parent.join(format!(
        ".oauth_tokens.{}.{}.tmp",
        std::process::id(),
        random_hex(8)
    ));
    let result = (|| -> Result<(), String> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("creating OAuth token temp file: {e}"))?;
        file.write_all(&body)
            .map_err(|e| format!("writing OAuth token temp file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("syncing OAuth token temp file: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("activating OAuth token store: {e}"))?;
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("syncing OAuth token store directory: {e}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
pub fn configure_persistent_store(identity_material: &str) -> Result<(), String> {
    let server_id = sha256_hex(identity_material.as_bytes());
    let dir = crate::cmd::init::config_dir();
    secure_store_dir(&dir)?;
    let path = dir.join(format!("oauth_tokens-{server_id}.json"));
    let tokens = load_tokens_from(&path, &server_id)?;
    STORE_CONFIG
        .set(StoreConfig { path, server_id })
        .map_err(|_| "OAuth token store configured more than once".to_string())?;
    STATE
        .set(Mutex::new(OauthState {
            codes: HashMap::new(),
            tokens,
        }))
        .map_err(|_| "OAuth state initialized before persistent store configuration".to_string())?;
    Ok(())
}

fn state() -> &'static Mutex<OauthState> {
    STATE.get_or_init(|| {
        Mutex::new(OauthState {
            codes: HashMap::new(),
            tokens: HashMap::new(),
        })
    })
}

#[cfg(not(test))]
fn persistent_store() -> Result<&'static StoreConfig, String> {
    STORE_CONFIG
        .get()
        .ok_or_else(|| "OAuth persistent store is not configured".to_string())
}

#[derive(Debug)]
pub enum TokenExchangeError {
    InvalidGrant(String),
    Server(String),
}

impl std::fmt::Display for TokenExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGrant(msg) | Self::Server(msg) => f.write_str(msg),
        }
    }
}

fn invalid_grant(message: impl Into<String>) -> TokenExchangeError {
    TokenExchangeError::InvalidGrant(message.into())
}

fn server_error(message: impl Into<String>) -> TokenExchangeError {
    TokenExchangeError::Server(message.into())
}
// ---------------------------------------------------------------------------
// Random helpers (no RNG crate — /dev/urandom only)
// ---------------------------------------------------------------------------

/// Read `n` random bytes from /dev/urandom and return them.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom must be available");
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).expect("reading /dev/urandom");
    buf
}

/// Generate a random URL-safe-base64 (no-pad) token from `n` raw bytes.
fn random_token(n: usize) -> String {
    URL_SAFE_NO_PAD.encode(random_bytes(n))
}

/// Generate a random hex string from `n` raw bytes.
fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/// Compute `BASE64URL-NOPAD(SHA256(ascii_verifier))` — the S256 code challenge
/// computed from a code verifier.
pub fn pkce_s256_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------------
// URL-encoded form parser (no extra crate)
// ---------------------------------------------------------------------------

/// Decode a percent-encoded URL component (`%XX` → byte, `+` → space).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte_val) = u8::from_str_radix(hex_str, 16) {
                    out.push(byte_val);
                    i += 3;
                    continue;
                }
            }
            // Not a valid %XX sequence — pass through literally.
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse an `application/x-www-form-urlencoded` body (or query string) into
/// a `HashMap<String, String>`. Keys and values are percent-decoded.
pub fn parse_urlencoded(input: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in input.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        map.insert(k, v);
    }
    map
}

// ---------------------------------------------------------------------------
// RFC 8414 — OAuth Authorization Server Metadata
// ---------------------------------------------------------------------------

/// Build the `/.well-known/oauth-authorization-server` discovery document.
pub fn discovery_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "registration_endpoint": format!("{issuer}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp"]
    })
}

// ---------------------------------------------------------------------------
// RFC 9728 — OAuth Protected Resource Metadata
// ---------------------------------------------------------------------------

/// Build the `/.well-known/oauth-protected-resource` document.
pub fn protected_resource_document(issuer: &str) -> serde_json::Value {
    serde_json::json!({
        "resource": issuer,
        "authorization_servers": [issuer]
    })
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

/// Handle `POST /register` — accept any client, return a generated client_id.
/// We accept any non-empty request body; the caller can send {} or a full RFC
/// 7591 document.
pub fn register() -> serde_json::Value {
    let client_id = format!("cgu-client-{}", random_hex(8));
    serde_json::json!({
        "client_id": client_id,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"]
    })
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

/// Return the HTML page for `GET /authorize?…` — a password form that re-posts
/// all existing query parameters as hidden fields alongside a `password` input.
pub fn authorize_form_html(query: &str) -> String {
    let params = parse_urlencoded(query);
    let mut hidden = String::new();
    for (k, v) in &params {
        // Escape for HTML attribute context.
        let k_esc = k
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let v_esc = v
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        hidden.push_str(&format!(
            r#"<input type="hidden" name="{k_esc}" value="{v_esc}">"#
        ));
        hidden.push('\n');
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MCP Server — Authorization</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background:#f5f5f5; display:flex; align-items:center; justify-content:center;
         min-height:100vh; margin:0; }}
  .card {{ background:#fff; border-radius:8px; padding:2rem 2.5rem;
           box-shadow:0 2px 12px rgba(0,0,0,.1); max-width:380px; width:100%; }}
  h1 {{ font-size:1.2rem; margin:0 0 1.2rem; color:#111; }}
  label {{ display:block; font-size:.85rem; color:#555; margin-bottom:.3rem; }}
  input[type=password] {{ width:100%; padding:.55rem .75rem; border:1px solid #ccc;
                          border-radius:5px; font-size:1rem; box-sizing:border-box; }}
  button {{ margin-top:1rem; width:100%; padding:.6rem; background:#0070f3; color:#fff;
            border:none; border-radius:5px; font-size:1rem; cursor:pointer; }}
  button:hover {{ background:#0060df; }}
  p.hint {{ font-size:.8rem; color:#888; margin-top:.8rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>MCP Server Authorization</h1>
  <form method="POST" action="/authorize">
    {hidden}
    <label for="pw">Server password</label>
    <input type="password" id="pw" name="password" autofocus required>
    <button type="submit">Authorize</button>
  </form>
  <p class="hint">Enter the token shown at server startup.</p>
</div>
</body>
</html>"#,
        hidden = hidden
    )
}

/// Handle `POST /authorize` (form submission).
///
/// `params` is a merged map of query string + form body fields.
/// On success, returns the redirect URL (`302 Location` target).
/// On failure, returns an error message for the `400` response.
pub fn authorize_submit(
    params: &HashMap<String, String>,
    server_password: &str,
) -> Result<String, String> {
    // Verify password.
    let pw = params.get("password").map(|s| s.as_str()).unwrap_or("");
    if pw != server_password {
        return Err("invalid password".to_string());
    }

    // PKCE: only S256 is supported.
    let method = params
        .get("code_challenge_method")
        .map(|s| s.as_str())
        .unwrap_or("");
    if method != "S256" {
        return Err(format!(
            "unsupported code_challenge_method: {method:?} (only S256 is supported)"
        ));
    }

    let code_challenge = params
        .get("code_challenge")
        .ok_or_else(|| "missing code_challenge".to_string())?
        .clone();

    let redirect_uri = params
        .get("redirect_uri")
        .ok_or_else(|| "missing redirect_uri".to_string())?
        .clone();

    let state_val = params.get("state").cloned().unwrap_or_default();

    // Generate and store the authorization code (10 minute TTL).
    let code = random_token(24);
    {
        let mut st = state().lock().unwrap();
        // Prune expired codes opportunistically.
        let now = Instant::now();
        st.codes.retain(|_, e| e.expiry > now);
        st.codes.insert(
            code.clone(),
            AuthCodeEntry {
                code_challenge,
                redirect_uri: redirect_uri.clone(),
                expiry: now + Duration::from_secs(600),
            },
        );
    }

    // Build redirect URL.
    let mut location = format!("{redirect_uri}?code={code}");
    if !state_val.is_empty() {
        location.push_str(&format!("&state={state_val}"));
    }
    Ok(location)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

/// Handle `POST /token` — exchange an authorization code for an access token.
///
/// `params` is the parsed form (or JSON) body.
/// Returns the token JSON on success, or an error string on failure.
pub fn exchange_token(
    params: &HashMap<String, String>,
) -> Result<serde_json::Value, TokenExchangeError> {
    let grant_type = params.get("grant_type").map(|s| s.as_str()).unwrap_or("");
    if grant_type != "authorization_code" {
        return Err(invalid_grant(format!(
            "unsupported grant_type: {grant_type:?}"
        )));
    }
    let code = params
        .get("code")
        .ok_or_else(|| invalid_grant("missing code"))?
        .clone();
    let verifier = params
        .get("code_verifier")
        .ok_or_else(|| invalid_grant("missing code_verifier"))?
        .clone();
    let redirect_uri = params
        .get("redirect_uri")
        .ok_or_else(|| invalid_grant("missing redirect_uri"))?
        .clone();

    let entry = {
        let mut st = state()
            .lock()
            .map_err(|_| server_error("OAuth state lock poisoned"))?;
        let now = Instant::now();
        st.codes.retain(|_, e| e.expiry > now);
        st.codes
            .remove(&code)
            .ok_or_else(|| invalid_grant("unknown or expired authorization code"))?
    };
    if entry.redirect_uri != redirect_uri {
        return Err(invalid_grant("redirect_uri mismatch"));
    }
    if pkce_s256_challenge(&verifier) != entry.code_challenge {
        return Err(invalid_grant(
            "PKCE verification failed: code_verifier does not match code_challenge",
        ));
    }

    let access_token = random_token(24);
    let digest = token_digest(&access_token);
    let now = unix_now().map_err(server_error)?;
    let expires_at = now
        .checked_add(ACCESS_TOKEN_TTL_SECS)
        .ok_or_else(|| server_error("access token expiry overflow"))?;
    let _writer = TOKEN_WRITER
        .lock()
        .map_err(|_| server_error("OAuth token writer lock poisoned"))?;
    let mut candidate = {
        let st = state()
            .lock()
            .map_err(|_| server_error("OAuth state lock poisoned"))?;
        st.tokens.clone()
    };
    candidate.retain(|_, entry| entry.expires_at > now);
    if candidate.len() >= MAX_PERSISTED_TOKENS {
        return Err(server_error("OAuth token store capacity reached"));
    }
    candidate.insert(digest, TokenEntry { expires_at });

    #[cfg(not(test))]
    {
        let config = persistent_store().map_err(server_error)?;
        persist_tokens_to(&config.path, &config.server_id, &candidate).map_err(server_error)?;
    }
    {
        let mut st = state()
            .lock()
            .map_err(|_| server_error("OAuth state lock poisoned"))?;
        st.tokens = candidate;
    }
    Ok(serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECS,
        "scope": "mcp"
    }))
}

// ---------------------------------------------------------------------------
// Bearer token validation
// ---------------------------------------------------------------------------

/// Returns `true` if `token` is a currently valid (non-expired) access token.
pub fn validate_bearer(token: &str) -> bool {
    let Ok(now) = unix_now() else {
        return false;
    };
    let digest = token_digest(token);
    let Ok(mut st) = state().lock() else {
        return false;
    };
    match st.tokens.get(&digest) {
        Some(entry) if entry.expires_at > now => true,
        Some(_) => {
            st.tokens.remove(&digest);
            false
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // (a) PKCE S256 — RFC 7636 test vector.
    // verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // expected challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    #[test]
    fn pkce_s256_rfc7636_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256_challenge(verifier), expected);
    }

    // (b) discovery_document contains the required fields/endpoints.
    #[test]
    fn discovery_document_has_required_fields() {
        let doc = discovery_document("https://example.com");
        assert_eq!(doc["issuer"], "https://example.com");
        assert_eq!(
            doc["authorization_endpoint"],
            "https://example.com/authorize"
        );
        assert_eq!(doc["token_endpoint"], "https://example.com/token");
        assert_eq!(doc["registration_endpoint"], "https://example.com/register");

        let grant_types = doc["grant_types_supported"].as_array().unwrap();
        assert!(grant_types.iter().any(|v| v == "authorization_code"));

        let methods = doc["code_challenge_methods_supported"].as_array().unwrap();
        assert!(methods.iter().any(|v| v == "S256"));

        let response_types = doc["response_types_supported"].as_array().unwrap();
        assert!(response_types.iter().any(|v| v == "code"));
    }

    // (c) Full authorize → token roundtrip: correct verifier succeeds; wrong fails.
    #[test]
    fn full_authorize_token_roundtrip() {
        // Build a PKCE pair.
        let verifier = "test_code_verifier_for_roundtrip_test_abc123xyz";
        let challenge = pkce_s256_challenge(verifier);

        let redirect_uri = "https://client.example.com/callback";
        let state_val = "random_state_value";

        // -- Authorize step --
        let mut auth_params = HashMap::new();
        auth_params.insert("code_challenge".to_string(), challenge.clone());
        auth_params.insert("code_challenge_method".to_string(), "S256".to_string());
        auth_params.insert("redirect_uri".to_string(), redirect_uri.to_string());
        auth_params.insert("state".to_string(), state_val.to_string());
        auth_params.insert("password".to_string(), "correct_password".to_string());

        let location = authorize_submit(&auth_params, "correct_password")
            .expect("authorize_submit should succeed with correct password");

        // Extract the code from the redirect URL.
        assert!(
            location.starts_with(redirect_uri),
            "redirect should point to redirect_uri"
        );
        let code = location
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find(|p| p.starts_with("code=")))
            .and_then(|p| p.strip_prefix("code="))
            .expect("redirect URL must contain code=…")
            .to_string();

        assert!(
            location.contains(&format!("state={state_val}")),
            "state must be preserved"
        );

        // -- Token exchange step: correct verifier --
        let mut token_params = HashMap::new();
        token_params.insert("grant_type".to_string(), "authorization_code".to_string());
        token_params.insert("code".to_string(), code.clone());
        token_params.insert("code_verifier".to_string(), verifier.to_string());
        token_params.insert("redirect_uri".to_string(), redirect_uri.to_string());

        let token_resp = exchange_token(&token_params).expect("token exchange should succeed");
        assert_eq!(token_resp["token_type"], "Bearer");
        let access_token = token_resp["access_token"].as_str().unwrap();
        assert!(!access_token.is_empty());
        assert!(validate_bearer(access_token), "issued token must be valid");

        // -- Replay: code is consumed; second use must fail --
        let mut replay_params = HashMap::new();
        replay_params.insert("grant_type".to_string(), "authorization_code".to_string());
        replay_params.insert("code".to_string(), code);
        replay_params.insert("code_verifier".to_string(), verifier.to_string());
        replay_params.insert("redirect_uri".to_string(), redirect_uri.to_string());
        assert!(
            exchange_token(&replay_params).is_err(),
            "replayed code must be rejected"
        );
    }

    #[test]
    fn token_exchange_fails_with_wrong_verifier() {
        let verifier = "correct_verifier_abcdefg12345";
        let challenge = pkce_s256_challenge(verifier);
        let redirect_uri = "https://client.example.com/cb";

        let mut auth_params = HashMap::new();
        auth_params.insert("code_challenge".to_string(), challenge);
        auth_params.insert("code_challenge_method".to_string(), "S256".to_string());
        auth_params.insert("redirect_uri".to_string(), redirect_uri.to_string());
        auth_params.insert("password".to_string(), "secret".to_string());

        let location = authorize_submit(&auth_params, "secret").unwrap();
        let code = location
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find(|p| p.starts_with("code=")))
            .and_then(|p| p.strip_prefix("code="))
            .unwrap()
            .to_string();

        let mut token_params = HashMap::new();
        token_params.insert("grant_type".to_string(), "authorization_code".to_string());
        token_params.insert("code".to_string(), code);
        token_params.insert("code_verifier".to_string(), "WRONG_verifier".to_string());
        token_params.insert("redirect_uri".to_string(), redirect_uri.to_string());

        let err = exchange_token(&token_params);
        assert!(err.is_err(), "wrong verifier must be rejected");
        let msg = err.unwrap_err();
        assert!(
            format!("{msg}").contains("PKCE"),
            "error should mention PKCE: {msg}"
        );
    }

    #[test]
    fn authorize_submit_rejects_wrong_password() {
        let mut params = HashMap::new();
        params.insert("code_challenge".to_string(), "x".to_string());
        params.insert("code_challenge_method".to_string(), "S256".to_string());
        params.insert(
            "redirect_uri".to_string(),
            "https://example.com/cb".to_string(),
        );
        params.insert("password".to_string(), "wrong".to_string());

        let err = authorize_submit(&params, "correct");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("invalid password"));
    }

    #[test]
    fn percent_decode_handles_plus_and_hex() {
        assert_eq!(percent_decode("hello+world"), "hello world");
        assert_eq!(percent_decode("foo%3Dbar"), "foo=bar");
        assert_eq!(percent_decode("a%20b%20c"), "a b c");
        assert_eq!(percent_decode("plain"), "plain");
    }

    #[test]
    fn parse_urlencoded_splits_correctly() {
        let m = parse_urlencoded("foo=bar&baz=qux&empty=");
        assert_eq!(m.get("foo").map(|s| s.as_str()), Some("bar"));
        assert_eq!(m.get("baz").map(|s| s.as_str()), Some("qux"));
        assert_eq!(m.get("empty").map(|s| s.as_str()), Some(""));
    }

    #[test]
    fn persisted_tokens_round_trip_and_prune_expired() {
        let dir = std::env::temp_dir().join(format!(
            "cgu-oauth-test-{}-{}",
            std::process::id(),
            random_hex(4)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oauth_tokens.json");
        let now = unix_now().unwrap();
        let mut tokens = HashMap::new();
        tokens.insert(
            "active".to_string(),
            TokenEntry {
                expires_at: now + 60,
            },
        );
        tokens.insert(
            "expired".to_string(),
            TokenEntry {
                expires_at: now.saturating_sub(1),
            },
        );
        persist_tokens_to(&path, "test-server", &tokens).unwrap();
        let loaded = load_tokens_from(&path, "test-server").unwrap();
        assert!(loaded.contains_key("active"));
        assert!(!loaded.contains_key("expired"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn validate_bearer_rejects_unknown_token() {
        assert!(!validate_bearer("not_a_real_token"));
    }
}
