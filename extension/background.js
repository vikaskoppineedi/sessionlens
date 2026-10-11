// Passive recorder. Only observes: no chrome.debugger, no blocking, no page changes.
// Every event is forwarded to the local ingest server, which owns ordering and storage.
importScripts('lib.js');

const { encodeRequestBody, shouldIgnoreRequest, claimNonce } = sessionlensLib;

const INGEST_URL = 'ws://127.0.0.1:8765/ingest';
const RECONNECT_MS = 2000;
const KEEPALIVE_MS = 20000; // an active WebSocket keeps the MV3 worker alive (< 30 s idle)
const SCREENSHOT_DELAY_MS = 800; // let the page react before capturing
const MAX_QUEUE = 10000;
const ALL_URLS = { urls: ['<all_urls>'] };

let socket = null;
let queue = [];
let dropped = 0;

function send(event) {
  if (queue.length >= MAX_QUEUE) {
    queue.shift();
    dropped++;
  }
  queue.push(JSON.stringify({ t: Date.now(), ...event }));
  flush();
}

function flush() {
  while (socket && socket.readyState === WebSocket.OPEN && queue.length) {
    socket.send(queue.shift());
  }
}

function connect() {
  socket = new WebSocket(INGEST_URL);
  socket.onopen = async () => {
    // Baseline cookie jar: the server rebuilds every later state from this plus cookie.change events.
    const cookies = await chrome.cookies.getAll({});
    socket.send(JSON.stringify({ t: Date.now(), type: 'hello', version: chrome.runtime.getManifest().version, cookies, dropped }));
    dropped = 0;
    flush();
    // Only the capture Chrome has sessionlens's claim tab; other profiles never claim, so the server ignores them.
    const tabs = await chrome.tabs.query({ url: 'http://127.0.0.1:8765/claim*' });
    tabs.forEach((tab) => sendClaim(tab.url));
  };
  socket.onclose = () => {
    socket = null;
    setTimeout(connect, RECONNECT_MS);
  };
}

function sendClaim(url) {
  const nonce = claimNonce(url);
  if (nonce && socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'claim', nonce }));
}

// The claim tab may finish loading after the socket opened.
chrome.tabs.onUpdated.addListener((_tabId, change) => sendClaim(change.url));

connect();
setInterval(() => socket?.readyState === WebSocket.OPEN && socket.send('{"type":"ping"}'), KEEPALIVE_MS);

// --- Requests -------------------------------------------------------------

function observe(webRequestEvent, toEvent, extraInfo) {
  webRequestEvent.addListener(
    (details) => {
      if (shouldIgnoreRequest(details, chrome.runtime.id)) return;
      send({ t: details.timeStamp, requestId: details.requestId, ...toEvent(details) });
    },
    ALL_URLS,
    extraInfo
  );
}

observe(chrome.webRequest.onBeforeRequest, (d) => ({
  type: 'req.start',
  url: d.url,
  method: d.method,
  resourceType: d.type,
  tabId: d.tabId,
  frameId: d.frameId,
  parentFrameId: d.parentFrameId,
  initiator: d.initiator,
  body: encodeRequestBody(d.requestBody),
}), ['requestBody']);

observe(chrome.webRequest.onSendHeaders, (d) => ({
  type: 'req.headers',
  headers: d.requestHeaders,
}), ['requestHeaders', 'extraHeaders']);

observe(chrome.webRequest.onHeadersReceived, (d) => ({
  type: 'resp.headers',
  statusCode: d.statusCode,
  statusLine: d.statusLine,
  headers: d.responseHeaders,
}), ['responseHeaders', 'extraHeaders']);

observe(chrome.webRequest.onBeforeRedirect, (d) => ({
  type: 'req.redirect',
  statusCode: d.statusCode,
  redirectUrl: d.redirectUrl,
  ip: d.ip,
  fromCache: d.fromCache,
}));

observe(chrome.webRequest.onCompleted, (d) => ({
  type: 'req.done',
  statusCode: d.statusCode,
  ip: d.ip,
  fromCache: d.fromCache,
}));

observe(chrome.webRequest.onErrorOccurred, (d) => ({
  type: 'req.error',
  error: d.error,
  fromCache: d.fromCache,
}));

// --- Cookies --------------------------------------------------------------

chrome.cookies.onChanged.addListener(({ removed, cookie, cause }) => {
  send({ type: 'cookie.change', removed, cause, cookie });
});

// --- Navigation -----------------------------------------------------------

function navEvent(type) {
  return (d) => {
    send({
      t: d.timeStamp,
      type,
      tabId: d.tabId,
      frameId: d.frameId,
      url: d.url,
      transitionType: d.transitionType,
      transitionQualifiers: d.transitionQualifiers,
    });
    if (d.frameId === 0) scheduleScreenshot(d.tabId);
  };
}

chrome.webNavigation.onCommitted.addListener(navEvent('nav.commit'));
chrome.webNavigation.onHistoryStateUpdated.addListener(navEvent('nav.history'));
chrome.webNavigation.onReferenceFragmentUpdated.addListener(navEvent('nav.fragment'));

// --- Actions and storage from content.js ----------------------------------

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!sender.tab) return;
  send({ ...message, tabId: sender.tab.id, frameId: sender.frameId, documentUrl: sender.url });
  if (message.type === 'action') scheduleScreenshot(sender.tab.id);
});

// --- Screenshots (debounced: a click followed by a navigation yields one) --

const screenshotTimers = new Map();

function scheduleScreenshot(tabId) {
  clearTimeout(screenshotTimers.get(tabId));
  screenshotTimers.set(tabId, setTimeout(() => captureScreenshot(tabId), SCREENSHOT_DELAY_MS));
}

async function captureScreenshot(tabId) {
  screenshotTimers.delete(tabId);
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.active) return; // captureVisibleTab only sees the active tab
    const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 50 });
    send({ type: 'screenshot', tabId, url: tab.url, dataUrl });
  } catch {
    // Tab closed, window minimised, or capture rate limit hit: skip this frame.
  }
}
