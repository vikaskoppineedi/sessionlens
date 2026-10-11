import type { Comparison, Model, RequestDetail, SessionInfo } from './types';

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'content-type': 'application/json', ...init?.headers },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail ?? response.statusText);
  return data as T;
}

export const api = {
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

/** Live model updates; reconnects if the server restarts. Returns a function that stops listening. */
export function subscribe(session: string, onModel: (m: Model) => void, onError: (msg: string) => void): () => void {
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
