import type { Comparison, Embedded, Model, RequestDetail, SessionInfo } from './types';

/** Reads the data blob that `export/index.html` carries; null when absent or unreadable. */
export function parseEmbedded(text: string | null): Embedded | null {
  if (!text) return null;
  try {
    const data: unknown = JSON.parse(text);
    if (typeof data !== 'object' || data === null || !('session' in data) || !('model' in data)) return null;
    return data as Embedded;
  } catch {
    return null;
  }
}

// The standalone report has no server: everything it can show is in this blob.
export const embedded = parseEmbedded(typeof document === 'undefined' ? null : (document.getElementById('sessionlens-data')?.textContent ?? null));
export const standalone = embedded !== null;

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'content-type': 'application/json', ...init?.headers },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail ?? response.statusText);
  return data as T;
}

const server = {
  sessions: () => call<SessionInfo[]>('/api/sessions'),
  detail: (session: string, request: string, reveal: boolean) =>
    call<RequestDetail>(`/api/sessions/${session}/requests/${encodeURIComponent(request)}?reveal=${reveal}`),
  replay: (session: string, request: string, body: { dropHeaders?: string[]; dropCookies?: string[]; allowUnsafe?: boolean }) =>
    call<Record<string, unknown>>(`/api/sessions/${session}/requests/${encodeURIComponent(request)}/replay`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  minimize: (session: string, request: string, allowUnsafe: boolean) =>
    call<Record<string, unknown>>(`/api/sessions/${session}/requests/${encodeURIComponent(request)}/minimize`, {
      method: 'POST',
      body: JSON.stringify({ allowUnsafe }),
    }),
  compare: (a: string, b: string) => call<Comparison>(`/api/compare?a=${a}&b=${b}`),
  screenshotUrl: (session: string, index: number) => `/api/sessions/${session}/screenshots/${index}`,
  exportUrl: (session: string) => `/api/sessions/${session}/export.zip`,
};

function fromEmbedded(data: Embedded): typeof server {
  return {
    ...server,
    sessions: () => Promise.resolve([{ id: data.session, live: false }]),
    detail: (_session, request) => {
      const detail = data.details[request];
      return detail ? Promise.resolve(detail) : Promise.reject(new Error('Not included in this report'));
    },
    screenshotUrl: (_session, index) => data.screenshots[String(index)] ?? '',
  };
}

export const api = embedded ? fromEmbedded(embedded) : server;

/** Live model updates; reconnects if the server restarts. Returns a function that stops listening. */
export function subscribe(session: string, onModel: (m: Model) => void, onError: (msg: string) => void): () => void {
  if (embedded) {
    onModel(embedded.model);
    return () => {};
  }
  let socket: WebSocket | null = null;
  let stopped = false;
  let retry: ReturnType<typeof setTimeout> | undefined;
  const connect = () => {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${proto}://${location.host}/api/sessions/${session}/live`);
    socket.onmessage = (event) => onModel(JSON.parse(event.data) as Model);
    socket.onclose = (event) => {
      if (stopped) return;
      if (event.code === 1008) onError('Session not found');
      else retry = setTimeout(connect, 2000);
    };
  };
  connect();
  return () => {
    stopped = true;
    clearTimeout(retry);
    socket?.close();
  };
}
