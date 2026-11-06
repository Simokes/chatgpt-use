const assert = require('node:assert/strict');
class Element {
  constructor(width, height) {
    this.rect = {width, height, left: 10, top: 20};
    this.attrs = {};
    this.textContent = '';
    this.value = '';
  }
  getBoundingClientRect() { return this.rect; }
  setAttribute(k, v) { this.attrs[k] = v; }
  removeAttribute(k) { delete this.attrs[k]; }
  hasAttribute(k) { return k in this.attrs; }
  getAttribute(k) { return this.attrs[k] ?? null; }
  closest(s) { assert.equal(s, 'form'); return this.form; }
  focus() { global.focused = this; }
  dispatchEvent() { this.opened = true; }
}
global.PointerEvent = class {};
let composers = [];
global.document = {
  querySelectorAll(s) {
    if (s === '#prompt-textarea, div.ProseMirror[contenteditable="true"][role="textbox"]') return composers;
    if (s === '[data-agent-review-active-composer]') return composers.filter(c => c.hasAttribute('data-agent-review-active-composer'));
    if (s === '[role="dialog"]') return [];
    throw Error('unexpected document selector: ' + s);
  }
};
function composer(width, height, label, marked = false) {
  const c = new Element(width, height);
  const picker = new Element(width ? 86 : 0, height ? 36 : 0);
  picker.textContent = label;
  picker.setAttribute('data-selected-reasoning-effort', 'high');
  if (marked) picker.setAttribute('data-codex-intelligence-trigger', 'true');
  const submit = new Element(20, 20);
  c.picker = picker;
  c.form = {
    querySelectorAll(s) {
      if (s.includes('data-codex-intelligence-trigger')) return marked ? [picker] : [];
      return [picker];
    },
    querySelector() { return submit; },
    requestSubmit(b) { assert.equal(b, submit); c.submitted = true; }
  };
  return c;
}
const run = name => JSON.parse(eval(scripts[name]));
for (const marked of [false, true]) {
  const hidden = composer(0, 0, 'hidden', true);
  const visible = composer(534, 26, 'visible', marked);
  hidden.value = 'old hidden draft';
  composers = [hidden, visible];
  assert.equal(run('find').label, 'visible');
  assert.equal(run('find').effort, 'high');
  assert.equal(run('presence').composer, true);
  assert.equal(run('open').ok, true);
  assert.equal(visible.picker.opened, true);
  assert.equal(hidden.picker.opened, undefined);
  assert.equal(run('prepare').ok, true);
  assert.equal(global.focused, visible);
  // The native editor adapter resolves the exact selector passed by Rust.
  const targets = document.querySelectorAll(selector);
  assert.deepEqual(targets, [visible]);
  targets[0].value = 'hello world';
  assert.equal(run('fingerprint').text, 'hello world');
  assert.equal(run('fingerprint').n, 10);
  assert.equal(run('fingerprint').h, 942532069);
  assert.equal(hidden.value, 'old hidden draft');
  assert.equal(run('submit').ok, true);
  assert.equal(visible.submitted, true);
  assert.equal(hidden.submitted, undefined);
}
for (const sizes of [[], [[0, 0]], [[534, 26], [100, 20]]]) {
  composers = sizes.map(([w, h]) => composer(w, h, 'candidate'));
  for (const name of Object.keys(scripts)) {
    assert.throws(() => run(name), new RegExp('active composer refused: found=' + composers.length + ', visible=' + composers.filter(c => c.rect.width > 0).length));
    assert.equal(composers.some(c => c.submitted), false);
  }
}
