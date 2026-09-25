//! MCP channel — a local MCP server that exposes this project's tools
//! (read_file / write_file / list_dir / grep / bash, from `crate::tools`) to a
//! *regular* GPT-5.5 conversation. Regular GPT-5.5 supports native MCP tool-calling,
//! so this is the no-role-play path (the browser channel can't do tools; this can).
//!
//! **Setup**: expose via a public tunnel (Cloudflare Tunnel / ngrok / Tailscale)
//! then register the public URL in ChatGPT > Settings > Apps as a custom MCP
//! connector. Copy `--token` into the connector header as `Authorization: Bearer
//! <token>`. NOTE: GPT-5.5 Pro cannot use MCP connectors — this channel targets
//! the regular GPT-5.5 tier only.
//!
//! **Transport**: plain HTTP JSON-RPC 2.0 on `POST /` (or `POST /mcp`).
//! SSE transport is not required for a first cut; add it later if ChatGPT requires
//! streaming. The accept loop stays responsive by handing requests to bounded workers;
//! MCP tool execution is serialized to one active request while OAuth/control routes remain available.
//!
//! **JSON-RPC methods implemented**:
//!   - `initialize`              → server capabilities + serverInfo
//!   - `notifications/initialized` → no-op (notification; no response sent)
//!   - `tools/list`              → MCP tool descriptors for every builtin spec
//!   - `tools/call`              → dispatch to `crate::tools::execute` (auto_approve=true)
//!
//! Owned by the MCP agent.

use crate::cli::{AuthMode, McpArgs, PermissionMode};
use crate::protocol::ToolCall;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{
    mpsc::{sync_channel, TrySendError},
    Arc,
};
use std::time::{Duration, Instant};

// ---- Request-id counter -----------------------------------------------------

/// Monotonically increasing counter used to generate unique tool-call ids.
/// No RNG needed; a static prefix + counter is deterministic and sufficient.
static CALL_COUNTER: AtomicU64 = AtomicU64::new(1);

const MAX_REQUEST_BODY: usize = 1024 * 1024;
const MAX_HTTP_INFLIGHT: usize = 32;
const MAX_OVERLOAD_QUEUE: usize = 64;
const MCP_SOCKET_IO_TIMEOUT_SECS: u64 = 5;
const MCP_HEADER_TIMEOUT_SECS: u64 = 10;
const MCP_BODY_TIMEOUT_SECS: u64 = 10;

struct CounterGuard {
    counter: Arc<AtomicUsize>,
}
impl Drop for CounterGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

struct McpSlotGuard {
    slot: Arc<AtomicBool>,
}
impl Drop for McpSlotGuard {
    fn drop(&mut self) {
        self.slot.store(false, Ordering::Release);
    }
}

fn try_acquire_mcp_slot(slot: Arc<AtomicBool>) -> Option<McpSlotGuard> {
    slot.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| McpSlotGuard { slot })
}

fn next_call_id() -> String {
    let n = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("mcp_call_{n}")
}

// ---- Auth helpers -----------------------------------------------------------

/// Check the `Authorization: Bearer <token>` header or `?token=<token>` query
/// parameter against the configured shared secret.
///
/// Returns `true` if auth is satisfied (i.e. no token configured, or the
/// provided value matches). Uses `==` on `&str` slices, which is not perfectly
/// constant-time on all platforms, but avoids early-return short-circuits that
/// would be an obvious timing oracle — good enough for a local tunnel gate.
fn auth_ok(request: &tiny_http::Request, expected: &str) -> bool {
    // Check Authorization header first.
    for header in request.headers() {
        if header.field.equiv("Authorization") {
            let val = header.value.as_str();
            if let Some(bearer) = val.strip_prefix("Bearer ") {
                return bearer == expected;
            }
            // Malformed Authorization header — fail.
            return false;
        }
    }

    // Fall back to ?token= query parameter.
    let url = request.url();
    if let Some(query) = url.split('?').nth(1) {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("token=") {
                return value == expected;
            }
        }
    }

    false
}

// ---- JSON-RPC helpers -------------------------------------------------------

/// A parsed JSON-RPC 2.0 request. `id` is None for notifications.
#[derive(Debug)]
struct JsonRpcRequest {
    id: Option<Value>,
    method: String,
    params: Value,
}

/// Parse the raw body bytes into a `JsonRpcRequest`.
/// Returns `Err` with a JSON-RPC parse-error response body on failure.
fn parse_jsonrpc(body: &str) -> std::result::Result<JsonRpcRequest, Value> {
    let v: Value = serde_json::from_str(body).map_err(|e| {
        json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": -32700, "message": format!("parse error: {e}") }
        })
    })?;

    let method = v
        .get("method")
        .and_then(|m| m.as_str())
        .ok_or_else(|| {
            json!({
                "jsonrpc": "2.0",
                "id": v.get("id").cloned().unwrap_or(Value::Null),
                "error": { "code": -32600, "message": "invalid request: missing method" }
            })
        })?
        .to_string();

    let id = v.get("id").cloned();
    let params = v.get("params").cloned().unwrap_or(Value::Null);

    Ok(JsonRpcRequest { id, method, params })
}

/// Build a JSON-RPC 2.0 success response.
fn ok_response(id: &Option<Value>, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone().unwrap_or(Value::Null),
        "result": result
    })
}

/// Build a JSON-RPC 2.0 error response.
fn err_response(id: &Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.clone().unwrap_or(Value::Null),
        "error": { "code": code, "message": message }
    })
}

// ---- MCP method handlers ----------------------------------------------------

/// `initialize` — advertise capabilities and server identity.
fn handle_initialize(id: &Option<Value>) -> Value {
    ok_response(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "chatgpt-use",
                "version": "0.0.1"
            }
        }),
    )
}

/// `tools/list` — map `crate::tools::builtin_specs()` to MCP tool descriptors.
///
/// Our `ToolSpec` uses `input_schema`; the MCP spec calls the same field
/// `inputSchema` (camelCase). We rename it here.
fn handle_tools_list(id: &Option<Value>, read_only: bool) -> Value {
    let specs = crate::tools::builtin_specs();
    let tools: Vec<Value> = specs
        .into_iter()
        .filter(|s| !read_only || crate::tools::is_read_only(&s.name))
        .map(|s| {
            json!({
                "name": s.name,
                "description": s.description,
                "inputSchema": s.input_schema
            })
        })
        .collect();

    ok_response(id, json!({ "tools": tools }))
}

/// `tools/call` — dispatch to `crate::tools::execute` and return MCP content.
///
/// Response shape:
/// ```json
/// {
///   "content": [{ "type": "text", "text": "<result text>" }],
///   "isError": false
/// }
/// ```
fn handle_tools_call(
    id: &Option<Value>,
    params: &Value,
    cwd: &std::path::Path,
    read_only: bool,
    perm: PermissionMode,
) -> Value {
    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => {
            return err_response(id, -32602, "tools/call: missing required param 'name'");
        }
    };

    // Workspace-exposed safety: under the read-only profile, refuse write/exec tools.
    if read_only && !crate::tools::is_read_only(&name) {
        return ok_response(
            id,
            json!({
                "content": [{ "type": "text", "text":
                    format!("tool '{name}' is disabled: this MCP server runs in the read-only profile (read_file/list_dir/grep only). Restart with --profile full on a trusted, non-exposed setup to enable write_file/bash.") }],
                "isError": true
            }),
        );
    }

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    let call = ToolCall {
        id: next_call_id(),
        name,
        input: arguments,
    };

    let result = crate::tools::execute(
        &call, cwd, true, /* auto_approve — no human in this loop */
        perm,
    );

    ok_response(
        id,
        json!({
            "content": [{ "type": "text", "text": result.content }],
            "isError": !result.ok
        }),
    )
}

// ---- Request dispatch -------------------------------------------------------

/// Dispatch a single JSON-RPC request and return the response body, or `None`
/// for notifications (requests without an `id`).
fn dispatch(
    req: &JsonRpcRequest,
    cwd: &std::path::Path,
    read_only: bool,
    perm: PermissionMode,
) -> Option<Value> {
    let id = &req.id;

    // Log every incoming request so connector activity is visible in mcp.log —
    // for tools/call, include the tool name + a short arg preview. This is how
    // you confirm ChatGPT's connector calls actually reach the server.
    if req.method == "tools/call" {
        let tool = req
            .params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let preview: String = req
            .params
            .get("arguments")
            .map(|a| a.to_string())
            .unwrap_or_default()
            .chars()
            .take(160)
            .collect();
        eprintln!("[mcp] → tools/call {tool} {preview}");
    } else {
        eprintln!("[mcp] → {}", req.method);
    }

    // Notifications (no `id`) → process but return no response.
    let is_notification = id.is_none();

    let response = match req.method.as_str() {
        "initialize" => handle_initialize(id),

        "notifications/initialized" => {
            // No-op notification. Return early — no response for notifications.
            return None;
        }

        "tools/list" => handle_tools_list(id, read_only),

        "tools/call" => handle_tools_call(id, &req.params, cwd, read_only, perm),

        other => err_response(id, -32601, &format!("method not found: {other}")),
    };

    if is_notification {
        None
    } else {
        Some(response)
    }
}

fn handle_http_request(
    mut request: tiny_http::Request,
    cwd: PathBuf,
    read_only: bool,
    permission_mode: PermissionMode,
    oauth_mode: bool,
    token: Option<String>,
    mcp_slot: Arc<AtomicBool>,
) {
    let (url_path, url_query) = {
        let url = request.url().to_string();
        if let Some(idx) = url.find('?') {
            (url[..idx].to_string(), url[idx + 1..].to_string())
        } else {
            (url, String::new())
        }
    };
    let method = request.method().clone();

    if oauth_mode {
        let issuer = issuer_from_request(&request);
        match (method.as_str(), url_path.as_str()) {
            ("GET", "/.well-known/oauth-authorization-server") => {
                let doc = crate::oauth::discovery_document(&issuer);
                respond_json(request, 200, doc.to_string());
                return;
            }
            ("GET", "/.well-known/oauth-protected-resource") => {
                let doc = crate::oauth::protected_resource_document(&issuer);
                respond_json(request, 200, doc.to_string());
                return;
            }
            ("POST", "/register") => {
                if let Err((status, message)) = read_body_bounded(&mut request) {
                    respond_body_error(request, status, message);
                    return;
                }
                let doc = crate::oauth::register();
                respond_json(request, 200, doc.to_string());
                return;
            }
            ("GET", "/authorize") => {
                let html = crate::oauth::authorize_form_html(&url_query);
                respond_html(request, 200, html);
                return;
            }
            ("POST", "/authorize") => {
                let body_str = match read_body_bounded(&mut request) {
                    Ok(body) => body,
                    Err((status, message)) => {
                        respond_body_error(request, status, message);
                        return;
                    }
                };
                let mut params = crate::oauth::parse_urlencoded(&url_query);
                params.extend(crate::oauth::parse_urlencoded(&body_str));
                let server_password = token.as_deref().unwrap_or("");
                match crate::oauth::authorize_submit(&params, server_password) {
                    Ok(location) => respond_redirect(request, &location),
                    Err(e) => respond_json(
                        request,
                        400,
                        json!({"error": "access_denied", "error_description": e}).to_string(),
                    ),
                }
                return;
            }
            ("POST", "/token") => {
                let is_json = is_json_content_type(&request);
                let body_str = match read_body_bounded(&mut request) {
                    Ok(body) => body,
                    Err((status, message)) => {
                        respond_body_error(request, status, message);
                        return;
                    }
                };
                let params = parse_token_body(&body_str, is_json);
                match crate::oauth::exchange_token(&params) {
                    Ok(token_resp) => respond_oauth_json(request, 200, token_resp.to_string()),
                    Err(crate::oauth::TokenExchangeError::InvalidGrant(e)) => respond_oauth_json(
                        request,
                        400,
                        json!({"error": "invalid_grant", "error_description": e}).to_string(),
                    ),
                    Err(crate::oauth::TokenExchangeError::Server(e)) => respond_oauth_json(
                        request,
                        500,
                        json!({"error": "server_error", "error_description": e}).to_string(),
                    ),
                }
                return;
            }
            _ => {}
        }
    }

    if method != tiny_http::Method::Post || (url_path != "/" && url_path != "/mcp") {
        respond_not_found(request);
        return;
    }

    let authed = if oauth_mode {
        let bearer = request.headers().iter().find_map(|h| {
            if h.field.equiv("Authorization") {
                h.value
                    .as_str()
                    .strip_prefix("Bearer ")
                    .map(|t| t.to_string())
            } else {
                None
            }
        });
        bearer
            .as_deref()
            .map(crate::oauth::validate_bearer)
            .unwrap_or(false)
    } else {
        match &token {
            Some(expected) => auth_ok(&request, expected),
            None => true,
        }
    };

    if !authed {
        let body = json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": { "code": -32000, "message": "unauthorized: invalid or missing token" }
        })
        .to_string();
        if oauth_mode {
            let issuer = issuer_from_request(&request);
            respond_oauth_unauthorized(request, &issuer, body);
        } else {
            respond_json(request, 401, body);
        }
        return;
    }

    let _mcp_guard = match try_acquire_mcp_slot(mcp_slot) {
        Some(guard) => guard,
        None => {
            let body = json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32001, "message": "MCP busy: another request is still executing" }
            }).to_string();
            respond_json(request, 503, body);
            return;
        }
    };

    let body_str = match read_body_bounded(&mut request) {
        Ok(body) => body,
        Err((status, message)) => {
            respond_body_error(request, status, message);
            return;
        }
    };

    let (status, response_body) = match parse_jsonrpc(&body_str) {
        Err(err_body) => (200u16, err_body.to_string()),
        Ok(rpc_req) => match dispatch(&rpc_req, &cwd, read_only, permission_mode) {
            None => {
                let resp = tiny_http::Response::empty(204);
                let _ = request.respond(resp);
                return;
            }
            Some(resp_value) => (200, resp_value.to_string()),
        },
    };
    respond_json(request, status, response_body);
}

// ---- Public entry point -----------------------------------------------------

// ---- HTTP response helpers --------------------------------------------------

/// Send a plain JSON response.
fn respond_json(request: tiny_http::Request, status: u16, body: String) {
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(
            "Content-Type: application/json"
                .parse::<tiny_http::Header>()
                .unwrap(),
        );
    let _ = request.respond(resp);
}

/// Build the RFC 9728 challenge that lets an OAuth client rediscover and
/// re-authorize this protected MCP resource after a missing/expired token.
fn oauth_www_authenticate_value(issuer: &str) -> String {
    let metadata_url = format!(
        "{}/.well-known/oauth-protected-resource",
        issuer.trim_end_matches('/')
    );
    let quoted = metadata_url.replace('\\', "\\\\").replace('"', "\\\"");
    format!("Bearer resource_metadata=\"{quoted}\"")
}

/// Send an OAuth 401 with protected-resource discovery metadata.
fn respond_oauth_unauthorized(request: tiny_http::Request, issuer: &str, body: String) {
    let challenge = oauth_www_authenticate_value(issuer);
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(401)
        .with_header(
            "Content-Type: application/json"
                .parse::<tiny_http::Header>()
                .unwrap(),
        )
        .with_header(
            format!("WWW-Authenticate: {challenge}")
                .parse::<tiny_http::Header>()
                .expect("OAuth WWW-Authenticate header must be valid"),
        )
        .with_header(
            "Cache-Control: no-store"
                .parse::<tiny_http::Header>()
                .unwrap(),
        )
        .with_header("Pragma: no-cache".parse::<tiny_http::Header>().unwrap());
    let _ = request.respond(resp);
}

/// Send an OAuth JSON response that must never be cached.
fn respond_oauth_json(request: tiny_http::Request, status: u16, body: String) {
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(
            "Content-Type: application/json"
                .parse::<tiny_http::Header>()
                .unwrap(),
        )
        .with_header(
            "Cache-Control: no-store"
                .parse::<tiny_http::Header>()
                .unwrap(),
        )
        .with_header("Pragma: no-cache".parse::<tiny_http::Header>().unwrap());
    let _ = request.respond(resp);
}

/// Send an HTML response.
fn respond_html(request: tiny_http::Request, status: u16, body: String) {
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(status)
        .with_header(
            "Content-Type: text/html; charset=utf-8"
                .parse::<tiny_http::Header>()
                .unwrap(),
        );
    let _ = request.respond(resp);
}

/// Send a 302 redirect.
fn respond_redirect(request: tiny_http::Request, location: &str) {
    let resp = tiny_http::Response::empty(302).with_header(
        format!("Location: {location}")
            .parse::<tiny_http::Header>()
            .unwrap(),
    );
    let _ = request.respond(resp);
}

/// Send a 404 JSON response.
fn respond_not_found(request: tiny_http::Request) {
    respond_json(request, 404, r#"{"error":"not found"}"#.to_string());
}

fn read_body_bounded(
    request: &mut tiny_http::Request,
) -> std::result::Result<String, (u16, String)> {
    if request
        .body_length()
        .is_some_and(|len| len > MAX_REQUEST_BODY)
    {
        return Err((
            413,
            format!("request body exceeds {MAX_REQUEST_BODY} bytes"),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(MCP_BODY_TIMEOUT_SECS);
    let mut body = Vec::with_capacity(request.body_length().unwrap_or(0).min(MAX_REQUEST_BODY));
    let mut buf = [0u8; 8192];
    let reader = request.as_reader();
    loop {
        if Instant::now() >= deadline {
            return Err((408, "request body deadline exceeded".to_string()));
        }
        let remaining = MAX_REQUEST_BODY + 1 - body.len();
        if remaining == 0 {
            return Err((
                413,
                format!("request body exceeds {MAX_REQUEST_BODY} bytes"),
            ));
        }
        let want = remaining.min(buf.len());
        match reader.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Err((408, "request body read timed out".to_string()));
            }
            Err(e) => return Err((400, format!("failed to read request body: {e}"))),
        }
    }
    if body.len() > MAX_REQUEST_BODY {
        return Err((
            413,
            format!("request body exceeds {MAX_REQUEST_BODY} bytes"),
        ));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn respond_body_error(request: tiny_http::Request, status: u16, message: String) {
    respond_json(request, status, json!({"error": message}).to_string());
}

// ---- Issuer derivation ------------------------------------------------------

/// Derive the OAuth issuer URL from the request's `Host` header.
/// ChatGPT reaches the server through the public tunnel, so we use
/// `https://{Host}` (no port re-emission — the tunnel host has no port).
fn issuer_from_request(request: &tiny_http::Request) -> String {
    for header in request.headers() {
        if header.field.equiv("Host") {
            let host = header.value.as_str();
            return format!("https://{host}");
        }
    }
    // Fallback: derive from the bind address (local dev).
    "http://localhost".to_string()
}

// ---- Content-type sniffing --------------------------------------------------

/// Return true if the request carries an `application/json` body (or no
/// Content-Type, where we also try JSON).
fn is_json_content_type(request: &tiny_http::Request) -> bool {
    for header in request.headers() {
        if header.field.equiv("Content-Type") {
            return header.value.as_str().contains("application/json");
        }
    }
    false
}

// ---- Token-body parser for /token endpoint ----------------------------------

/// Parse the `POST /token` body — accepts either JSON or urlencoded form.
fn parse_token_body(body: &str, is_json: bool) -> HashMap<String, String> {
    if is_json {
        // Flatten a JSON object into a string map.
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str(body) {
            return map
                .into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect();
        }
    }
    crate::oauth::parse_urlencoded(body)
}

// ---- Public entry point -----------------------------------------------------

/// Start the MCP JSON-RPC server and block serving requests.
pub fn run(args: &McpArgs) -> Result<()> {
    let cwd: PathBuf = match &args.cwd {
        Some(p) => PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    let read_only = matches!(args.profile, crate::cli::ToolProfile::ReadOnly);
    // Effective token: --token wins, else the one saved by `chatgpt-use init`.
    let token: Option<String> = args.token.clone().or_else(crate::cmd::init::load_token);
    if token
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| value.is_empty())
    {
        return Err(anyhow::anyhow!(
            "MCP authentication secret must not be empty"
        ));
    }

    let oauth_mode = args.auth_mode == AuthMode::OAuth;
    if oauth_mode {
        let password = token.as_deref().ok_or_else(|| {
            anyhow::anyhow!("OAuth mode requires a configured server password; run `chatgpt-use init` or pass --token")
        })?;
        let identity_material = format!(
            "mcp-oauth-v1|host={}|port={}|profile={:?}|permission={:?}|password={}",
            args.host, args.port, args.profile, args.permission_mode, password
        );
        crate::oauth::configure_persistent_store(&identity_material)
            .map_err(|e| anyhow::anyhow!("failed to initialize OAuth token store: {e}"))?;
    }

    let bind_addr = format!("{}:{}", args.host, args.port);
    let connection_policy = tiny_http::ConnectionPolicy {
        single_request: true,
        read_timeout: Some(Duration::from_secs(MCP_SOCKET_IO_TIMEOUT_SECS)),
        write_timeout: Some(Duration::from_secs(MCP_SOCKET_IO_TIMEOUT_SECS)),
        header_timeout: Some(Duration::from_secs(MCP_HEADER_TIMEOUT_SECS)),
    };
    let server = tiny_http::Server::http_with_connection_policy(&bind_addr, connection_policy)
        .map_err(|e| anyhow::anyhow!("failed to bind MCP server on {bind_addr}: {e}"))?;

    eprintln!("[mcp] listening on http://{bind_addr}");
    eprintln!("[mcp] cwd: {}", cwd.display());
    eprintln!(
        "[mcp] profile: {} ({})",
        if read_only { "read-only" } else { "full" },
        if read_only {
            "read_file/list_dir/grep"
        } else {
            "ALL tools incl. write_file + bash — trusted/local only"
        }
    );
    // Under --profile full, `bash` becomes a PERSISTENT terminal: cwd + exported
    // env carry over between calls, bounded by --bash-timeout. (Read-only profile
    // never exposes bash, so there's nothing to configure.)
    if !read_only {
        let state_dir = crate::cmd::init::config_dir().join("shell");
        crate::tools::configure_shell(state_dir, args.bash_timeout);
        let limit = if args.bash_timeout == 0 {
            "no timeout".to_string()
        } else {
            format!("{}s/command timeout", args.bash_timeout)
        };
        eprintln!("[mcp] bash: persistent terminal (cwd + env persist; {limit})");
        if matches!(args.permission_mode, crate::cli::PermissionMode::Dangerous) {
            eprintln!("[mcp] WARNING: --permission-mode dangerous → UNRESTRICTED shell. Anyone with the URL + token gets a terminal on this machine. Keep the token secret; prefer not tunneling.");
        } else {
            eprintln!(
                "[mcp] bash gating: --permission-mode {:?} (use dangerous for an unrestricted terminal)",
                args.permission_mode
            );
        }
    }
    // Skill discovery (list_skills/read_skill): default ~/.claude/skills; empty disables.
    if let Some(sd) = &args.skills_dir {
        crate::tools::configure_skills(std::path::PathBuf::from(sd));
        if sd.is_empty() {
            eprintln!("[mcp] skills: discovery DISABLED (--skills-dir \"\")");
        } else {
            eprintln!("[mcp] skills: list_skills/read_skill → {sd}");
        }
    } else {
        let default = crate::cmd::init::config_dir()
            .parent()
            .map(|p| p.join(".claude").join("skills"))
            .unwrap_or_default();
        // configure_skills not called → tools fall back to ~/.claude/skills.
        eprintln!(
            "[mcp] skills: list_skills/read_skill → {} (default)",
            default.display()
        );
    }
    if oauth_mode {
        eprintln!("[mcp] auth: OAuth 2.1 + PKCE — password configured");
    } else if token.is_some() {
        eprintln!("[mcp] auth: Bearer token required");
    } else {
        eprintln!("[mcp] auth: NONE — consider --token when tunneling");
    }
    eprintln!("[mcp] tunnel hint: expose with  cloudflared tunnel --url http://{bind_addr}");
    eprintln!(
        "[mcp]   then register the public URL in ChatGPT > Settings > Apps > Add custom connector"
    );

    let mcp_slot = Arc::new(AtomicBool::new(false));
    let http_inflight = Arc::new(AtomicUsize::new(0));
    // Keep overload handling bounded too. A slow client that never reads its 503
    // may occupy this one responder, but it cannot create an unbounded number of
    // reject threads; once the bounded queue fills, new overload requests are
    // dropped (closing their connections) directly from the accept loop.
    let (overload_tx, overload_rx) = sync_channel::<tiny_http::Request>(MAX_OVERLOAD_QUEUE);
    std::thread::Builder::new()
        .name("mcp-http-overload".to_string())
        .spawn(move || {
            while let Ok(request) = overload_rx.recv() {
                respond_json(
                    request,
                    503,
                    json!({"error": "server busy: too many concurrent HTTP requests"}).to_string(),
                );
            }
        })
        .map_err(|e| anyhow::anyhow!("failed to spawn bounded HTTP overload responder: {e}"))?;

    loop {
        let request = server.recv()?;
        let previous = http_inflight.fetch_add(1, Ordering::AcqRel);
        if previous >= MAX_HTTP_INFLIGHT {
            http_inflight.fetch_sub(1, Ordering::AcqRel);
            match overload_tx.try_send(request) {
                Ok(()) => {}
                Err(TrySendError::Full(_request)) => {
                    // Dropping the request closes the connection. Never block the
                    // accept loop waiting for a slow overload client.
                }
                Err(TrySendError::Disconnected(_request)) => {
                    eprintln!("[mcp] overload responder stopped; dropping busy request");
                }
            }
            continue;
        }

        let counter = http_inflight.clone();
        let guard = CounterGuard { counter };
        let request_cwd = cwd.clone();
        let request_token = token.clone();
        let request_mcp_slot = mcp_slot.clone();
        let permission_mode = args.permission_mode;
        let spawn = std::thread::Builder::new()
            .name("mcp-http-worker".to_string())
            .spawn(move || {
                let _http_guard = guard;
                handle_http_request(
                    request,
                    request_cwd,
                    read_only,
                    permission_mode,
                    oauth_mode,
                    request_token,
                    request_mcp_slot,
                );
            });
        if let Err(e) = spawn {
            eprintln!("[mcp] failed to spawn HTTP worker: {e}");
        }
    }
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn oauth_401_challenge_advertises_protected_resource_metadata() {
        assert_eq!(
            oauth_www_authenticate_value("https://example.test"),
            "Bearer resource_metadata=\"https://example.test/.well-known/oauth-protected-resource\""
        );
        assert_eq!(
            oauth_www_authenticate_value("https://example.test/"),
            "Bearer resource_metadata=\"https://example.test/.well-known/oauth-protected-resource\""
        );
    }

    // --- parse_jsonrpc ---

    #[test]
    fn parse_valid_request_with_id() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let req = parse_jsonrpc(raw).expect("should parse");
        assert_eq!(req.method, "initialize");
        assert_eq!(req.id, Some(json!(1)));
    }

    #[test]
    fn parse_notification_has_no_id() {
        let raw = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        let req = parse_jsonrpc(raw).expect("should parse notification");
        assert_eq!(req.method, "notifications/initialized");
        assert!(req.id.is_none(), "notification should have no id");
    }

    #[test]
    fn parse_malformed_json_returns_error() {
        let raw = r#"{"jsonrpc":"2.0","id":1,BROKEN}"#;
        let err = parse_jsonrpc(raw).expect_err("should fail on malformed JSON");
        assert_eq!(err["error"]["code"], -32700);
    }

    #[test]
    fn parse_missing_method_returns_invalid_request() {
        let raw = r#"{"jsonrpc":"2.0","id":2,"params":{}}"#;
        let err = parse_jsonrpc(raw).expect_err("should fail without method");
        assert_eq!(err["error"]["code"], -32600);
    }

    // --- handle_initialize ---

    #[test]
    fn initialize_returns_correct_shape() {
        let id = Some(json!(42));
        let resp = handle_initialize(&id);
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["serverInfo"]["name"], "chatgpt-use");
        assert_eq!(resp["result"]["serverInfo"]["version"], "0.0.1");
        assert!(resp["result"]["capabilities"]["tools"].is_object());
    }

    // --- handle_tools_list ---

    #[test]
    fn tools_list_contains_all_builtins() {
        let id = Some(json!("req-1"));
        let resp = handle_tools_list(&id, false);
        let tools = resp["result"]["tools"]
            .as_array()
            .expect("tools should be array");
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"read_file"));
        assert!(names.contains(&"write_file"));
        assert!(names.contains(&"list_dir"));
        assert!(names.contains(&"grep"));
        assert!(names.contains(&"bash"));
    }

    #[test]
    fn read_only_profile_hides_and_blocks_write_tools() {
        // tools/list under read-only shows only read_file/list_dir/grep.
        let id = Some(json!(1));
        let resp = handle_tools_list(&id, true);
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(
            names.contains(&"read_file") && names.contains(&"list_dir") && names.contains(&"grep")
        );
        assert!(
            !names.contains(&"write_file"),
            "write_file must be hidden in read-only"
        );
        assert!(!names.contains(&"bash"), "bash must be hidden in read-only");

        // tools/call to a write tool under read-only is refused with isError.
        let params = json!({ "name": "bash", "arguments": { "command": "echo hi" } });
        let resp = handle_tools_call(
            &id,
            &params,
            &std::env::temp_dir(),
            true,
            PermissionMode::Dangerous,
        );
        assert_eq!(resp["result"]["isError"], json!(true));
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("read-only"),
            "should explain the read-only profile: {text}"
        );
    }

    #[test]
    fn tools_list_uses_input_schema_camel_case() {
        let id = Some(json!(1));
        let resp = handle_tools_list(&id, false);
        let tools = resp["result"]["tools"].as_array().unwrap();
        for tool in tools {
            assert!(
                tool.get("inputSchema").is_some(),
                "tool '{}' should have 'inputSchema' (camelCase)",
                tool["name"]
            );
            assert!(
                tool.get("input_schema").is_none(),
                "tool '{}' must NOT expose snake_case 'input_schema'",
                tool["name"]
            );
        }
    }

    // --- handle_tools_call ---

    #[test]
    fn tools_call_missing_name_returns_error() {
        let id = Some(json!(3));
        let params = json!({ "arguments": {} });
        let cwd = std::env::temp_dir();
        let resp = handle_tools_call(&id, &params, &cwd, false, PermissionMode::Dangerous);
        assert_eq!(resp["error"]["code"], -32602);
    }

    #[test]
    fn tools_call_unknown_tool_returns_is_error_true() {
        let id = Some(json!(4));
        let params = json!({ "name": "no_such_tool", "arguments": {} });
        let cwd = std::env::temp_dir();
        let resp = handle_tools_call(&id, &params, &cwd, false, PermissionMode::Dangerous);
        // Unknown tool: tools::execute returns ok=false, which maps to isError=true.
        assert_eq!(resp["result"]["isError"], true);
        let content = &resp["result"]["content"][0];
        assert_eq!(content["type"], "text");
        assert!(content["text"].as_str().unwrap().contains("unknown tool"));
    }

    #[test]
    fn tools_call_read_file_succeeds() {
        use std::fs;
        let dir = std::env::temp_dir().join(format!("mcp-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("hello.txt"), "hello from mcp test").unwrap();

        let id = Some(json!(5));
        let params = json!({ "name": "read_file", "arguments": { "path": "hello.txt" } });
        let resp = handle_tools_call(&id, &params, &dir, false, PermissionMode::Dangerous);

        assert_eq!(resp["result"]["isError"], false);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hello from mcp test"));
    }

    // --- dispatch ---

    #[test]
    fn dispatch_notification_returns_none() {
        let rpc = JsonRpcRequest {
            id: None,
            method: "notifications/initialized".to_string(),
            params: Value::Null,
        };
        let result = dispatch(
            &rpc,
            &std::env::temp_dir(),
            false,
            PermissionMode::Dangerous,
        );
        assert!(result.is_none(), "notifications should produce no response");
    }

    #[test]
    fn dispatch_unknown_method_returns_method_not_found() {
        let rpc = JsonRpcRequest {
            id: Some(json!(99)),
            method: "bogus/method".to_string(),
            params: Value::Null,
        };
        let result = dispatch(
            &rpc,
            &std::env::temp_dir(),
            false,
            PermissionMode::Dangerous,
        )
        .unwrap();
        assert_eq!(result["error"]["code"], -32601);
    }

    // --- next_call_id ---

    #[test]
    fn call_ids_are_unique() {
        let a = next_call_id();
        let b = next_call_id();
        assert_ne!(a, b);
        assert!(a.starts_with("mcp_call_"));
    }
}
