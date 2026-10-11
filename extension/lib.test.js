const test = require('node:test');
const assert = require('node:assert/strict');
const lib = require('./lib.js');

test('encodeRequestBody returns null when there is no body', () => {
  assert.equal(lib.encodeRequestBody(undefined), null);
});

test('encodeRequestBody keeps parsed form data', () => {
  const body = { formData: { username: ['demo'], csrf: ['abc'] } };
  assert.deepEqual(lib.encodeRequestBody(body), { formData: body.formData });
});

test('encodeRequestBody base64-encodes raw bytes and keeps file parts', () => {
  const bytes = new TextEncoder().encode('{"q":"ü"}').buffer;
  const result = lib.encodeRequestBody({ raw: [{ bytes }, { file: '/tmp/a.png' }] });
  assert.deepEqual(result, {
    raw: [{ base64: Buffer.from('{"q":"ü"}').toString('base64') }, { file: '/tmp/a.png' }],
  });
});

test('encodeRequestBody reports Chrome body errors', () => {
  assert.deepEqual(lib.encodeRequestBody({ error: 'Unknown error.' }), { error: 'Unknown error.' });
});

test('elementText never exposes password values', () => {
  assert.equal(lib.elementText({ tagName: 'INPUT', type: 'password', value: 'hunter2' }), '');
});

test('elementText uses value for input buttons and trims long text', () => {
  assert.equal(lib.elementText({ tagName: 'INPUT', type: 'submit', value: ' Sign in ' }), 'Sign in');
  assert.equal(lib.elementText({ tagName: 'BUTTON', innerText: 'x'.repeat(200) }).length, 80);
});

test('elementText ignores typed values of text inputs', () => {
  assert.equal(lib.elementText({ tagName: 'INPUT', type: 'text', value: 'typed' }), '');
});

test('describeForm redacts passwords and skips unnamed fields', () => {
  const form = {
    elements: [
      { name: 'username', type: 'text', value: 'demo' },
      { name: 'password', type: 'password', value: 'hunter2' },
      { name: 'remember', type: 'checkbox', value: 'on', checked: false },
      { name: '', type: 'submit', value: 'Go' },
    ],
  };
  assert.deepEqual(lib.describeForm(form), [
    { name: 'username', type: 'text', value: 'demo' },
    { name: 'password', type: 'password', value: '[redacted]' },
    { name: 'remember', type: 'checkbox', value: false },
  ]);
});

function el(tagName, props = {}) {
  return { tagName, id: '', className: '', parentElement: null, children: [], ...props };
}

test('cssPath stops at an element with an id', () => {
  const root = el('DIV', { id: 'app' });
  const button = el('BUTTON', { className: 'btn primary', parentElement: root });
  root.children = [button];
  assert.equal(lib.cssPath(button), 'div#app > button.btn.primary');
});

test('cssPath adds nth-of-type for ambiguous siblings', () => {
  const list = el('UL');
  const a = el('LI', { parentElement: list });
  const b = el('LI', { parentElement: list });
  list.children = [a, b];
  assert.equal(lib.cssPath(b), 'ul > li:nth-of-type(2)');
});

test('snapshotStorage copies all keys, including unicode', () => {
  const data = { token: 'eyJ', 'ключ': '值' };
  const keys = Object.keys(data);
  const storage = { length: keys.length, key: (i) => keys[i], getItem: (k) => data[k] };
  assert.deepEqual(lib.snapshotStorage(storage), data);
});

test('claimNonce reads the nonce from the claim page only', () => {
  assert.equal(lib.claimNonce('http://127.0.0.1:8765/claim?nonce=abc123'), 'abc123');
  assert.equal(lib.claimNonce('http://127.0.0.1:8765/claim?nonce=abc&x=1'), 'abc');
  assert.equal(lib.claimNonce('https://evil.com/claim?nonce=abc'), null);
  assert.equal(lib.claimNonce(undefined), null);
});

test('shouldIgnoreRequest skips own traffic only', () => {
  const extId = 'abc';
  assert.equal(lib.shouldIgnoreRequest({ url: 'ws://127.0.0.1:8765/ingest' }, extId), true);
  assert.equal(lib.shouldIgnoreRequest({ url: 'http://127.0.0.1:8765/claim?nonce=x' }, extId), true);
  assert.equal(lib.shouldIgnoreRequest({ url: 'http://127.0.0.1:8080/' }, extId), false);
  assert.equal(lib.shouldIgnoreRequest({ url: 'https://x.com', initiator: 'chrome-extension://abc' }, extId), true);
  assert.equal(lib.shouldIgnoreRequest({ url: 'https://x.com', initiator: 'https://x.com' }, extId), false);
});
