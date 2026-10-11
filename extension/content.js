// Runs in Chrome's isolated world: the page cannot see these listeners or variables.
// Listen-only. Never modifies the DOM, never patches page APIs.
(function () {
  const { cssPath, elementText, describeForm, snapshotStorage } = sessionlensLib;

  const STORAGE_POLL_MS = 1000;
  const LISTEN = { capture: true, passive: true };
  const INTERACTIVE = 'a,button,input,select,textarea,label,summary,[role=button],[onclick]';

  let pollTimer = null;

  function emit(message) {
    try {
      chrome.runtime.sendMessage({ t: Date.now(), ...message }).catch(() => {});
    } catch {
      clearInterval(pollTimer); // extension reloaded: this script is orphaned
    }
  }

  window.addEventListener('click', (event) => {
    if (!(event.target instanceof Element)) return;
    const target = event.target.closest(INTERACTIVE) || event.target;
    emit({
      type: 'action',
      action: 'click',
      selector: cssPath(target),
      tag: target.tagName.toLowerCase(),
      text: elementText(target),
      href: target.href || null,
      x: event.clientX,
      y: event.clientY,
    });
  }, LISTEN);

  window.addEventListener('submit', (event) => {
    const form = event.target;
    emit({
      type: 'action',
      action: 'submit',
      selector: cssPath(form),
      formAction: form.action,
      formMethod: form.method,
      fields: describeForm(form),
    });
  }, LISTEN);

  window.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' || !(event.target instanceof HTMLInputElement)) return;
    emit({ type: 'action', action: 'enter', selector: cssPath(event.target), tag: 'input' });
  }, LISTEN);

  // Storage has no change event for the same document, so poll and send full snapshots on change.
  const last = { local: null, session: null };

  function pollStorage() {
    for (const [area, storage] of [['local', window.localStorage], ['session', window.sessionStorage]]) {
      let items;
      try {
        items = snapshotStorage(storage);
      } catch {
        continue; // sandboxed or opaque-origin frame
      }
      const serialized = JSON.stringify(items);
      if (serialized === last[area]) continue;
      const isFirstEmpty = last[area] === null && serialized === '{}';
      last[area] = serialized;
      if (!isFirstEmpty) emit({ type: 'storage', area, origin: location.origin, items });
    }
  }

  pollStorage();
  pollTimer = setInterval(pollStorage, STORAGE_POLL_MS);
})();
