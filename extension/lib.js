// Pure helpers shared by background.js, content.js and node tests.
// Content scripts run in an isolated world, so this global is invisible to the page.
(function (root) {
  const INGEST_HOST = '127.0.0.1:8765';
  const CLAIM_PREFIX = `http://${INGEST_HOST}/claim?nonce=`;
  const MAX_TEXT = 80;
  const MAX_PATH_DEPTH = 5;

  function bytesToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
  }

  // webRequest gives either parsed formData, raw byte chunks, or an error.
  function encodeRequestBody(requestBody) {
    if (!requestBody) return null;
    if (requestBody.error) return { error: requestBody.error };
    if (requestBody.formData) return { formData: requestBody.formData };
    if (requestBody.raw) {
      return {
        raw: requestBody.raw.map((part) =>
          part.bytes ? { base64: bytesToBase64(part.bytes) } : { file: part.file }
        ),
      };
    }
    return null;
  }

  // Visible label of a clicked element. Never reads what the user typed.
  function elementText(el) {
    if (el.tagName === 'INPUT') {
      const isButton = ['submit', 'button', 'reset'].includes(el.type);
      return isButton ? String(el.value || '').trim().slice(0, MAX_TEXT) : '';
    }
    return String(el.innerText || '').trim().slice(0, MAX_TEXT);
  }

  function describeForm(form) {
    return Array.from(form.elements)
      .filter((field) => field.name)
      .map((field) => {
        let value = field.value;
        if (field.type === 'password') value = '[redacted]';
        else if (field.type === 'checkbox' || field.type === 'radio') value = field.checked;
        return { name: field.name, type: field.type, value };
      });
  }

  function cssSegment(el) {
    let segment = el.tagName.toLowerCase();
    if (el.id) return `${segment}#${el.id}`;
    const classes = String(el.className || '').trim().split(/\s+/).filter(Boolean);
    if (classes.length) segment += '.' + classes.join('.');
    const parent = el.parentElement;
    if (parent) {
      const sameTag = Array.from(parent.children).filter((c) => c.tagName === el.tagName);
      if (sameTag.length > 1) segment += `:nth-of-type(${sameTag.indexOf(el) + 1})`;
    }
    return segment;
  }

  function cssPath(el) {
    const parts = [];
    for (let node = el; node && parts.length < MAX_PATH_DEPTH; node = node.parentElement) {
      parts.unshift(cssSegment(node));
      if (node.id) break;
    }
    return parts.join(' > ');
  }

  function snapshotStorage(storage) {
    const items = {};
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      items[key] = storage.getItem(key);
    }
    return items;
  }

  function shouldIgnoreRequest(details, extensionId) {
    if (/^(ws|http):\/\/127\.0\.0\.1:8765\//.test(details.url)) return true; // sessionlens's own server
    return details.initiator === `chrome-extension://${extensionId}`;
  }

  // sessionlens launches the capture Chrome on its claim page; the nonce proves which browser to record.
  function claimNonce(url) {
    return url && url.startsWith(CLAIM_PREFIX) ? url.slice(CLAIM_PREFIX.length).split('&')[0] : null;
  }

  const lib = { encodeRequestBody, elementText, describeForm, cssPath, snapshotStorage, shouldIgnoreRequest, claimNonce };
  if (typeof module === 'object' && module.exports) module.exports = lib;
  else root.sessionlensLib = lib;
})(globalThis);
