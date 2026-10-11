// Mirrors sessionlens/model.py output.

export type CellState = 'absent' | 'added' | 'changed' | 'removed' | 'same';

export interface Cell {
  state: CellState;
  value?: string | null;
  touched?: boolean;
}

export interface Lineage {
  t: number;
  step: number;
  source: 'header' | 'javascript' | 'browser' | 'resync' | '';
  request: string | null;
  cause?: string;
}

export interface Row {
  id: string;
  group: 'cookie' | 'local' | 'session';
  section: string;
  name: string;
  cells: Cell[];
  initial?: string | null;
  badges: string[];
  domain?: string;
  path?: string;
  attrs?: Record<string, unknown>;
  setBy?: Lineage[];
  removedBy?: Lineage[];
  sentBy?: string[];
  persistence?: { onDisk: boolean; since?: number; note?: string };
}

export interface Step {
  id: number;
  t: number;
  kind: 'start' | 'action' | 'nav' | 'spa';
  label: string;
  url: string | null;
  screenshot: number | null;
}

export interface RequestSummary {
  id: string;
  step: number;
  t: number;
  method: string;
  url: string;
  status: number | null;
  resourceType: string | null;
  initiator: string | null;
  tabId: number | null;
  frameId: number | null;
  match: 'matched' | 'ambiguous' | 'ext-only' | 'wire-only' | 'cache';
  proto: string | null;
  redirectTo: string | null;
  fromCache: boolean;
  error: string | null;
  browserInternal: boolean;
  cookiesSent: string[];
  cookiesSet: string[];
  blocked: number;
}

export interface Body {
  kind: 'none' | 'form' | 'json' | 'text' | 'binary' | 'skipped' | 'unavailable';
  size?: number;
  contentType?: string;
  form?: [string, string][];
  json?: unknown;
  text?: string;
  truncated?: boolean;
  hexPreview?: string;
  reason?: string;
  decodeError?: string;
}

export interface SetCookieOutcome {
  name: string;
  value: string;
  attrs: Record<string, string>;
  raw: string;
  rowId: string | null;
  outcome: 'stored' | 'deleted' | 'unchanged' | 'blocked';
  reason?: string;
}

export type Headers = [string, string][];

export interface RequestDetail extends Omit<RequestSummary, 'cookiesSet'> {
  query: [string, string][];
  requestHeaders: { wire: Headers | null; ext: Headers | null };
  responseHeaders: { wire: Headers | null; ext: Headers | null };
  requestBody: Body;
  responseBody: Body;
  cookiesSentValues: { name: string; value: string }[];
  cookiesSet: SetCookieOutcome[];
  timing: { start: number; response: number | null; wireRequest: number | null };
}

export interface DiskRow {
  kind: string;
  label: string;
  cells: { count: number; items: Record<string, unknown>[] }[];
}

export interface Blocked {
  request: string;
  step: number;
  name: string;
  raw: string;
  reason: string;
}

export interface Model {
  steps: Step[];
  rows: Row[];
  requests: RequestSummary[];
  blocked: Blocked[];
  disk: DiskRow[];
  status: {
    extensionEvents: number;
    lastExtensionEvent: number | null;
    wireMessages: number;
    diskSnapshots: number;
    components: Record<string, { ok: boolean; detail: string; t: number }>;
  };
  live: boolean;
}

export interface SessionInfo {
  id: string;
  live: boolean;
}

/** Data blob in `export/index.html` (written by `report.py`). `screenshots` maps screenshot index to a relative path. */
export interface Embedded {
  session: string;
  model: Model;
  details: Record<string, RequestDetail>;
  screenshots: Record<string, string>;
}

export interface Comparison {
  cookies: { onlyA: string[]; onlyB: string[]; both: string[] };
  endpoints: { onlyA: string[]; onlyB: string[]; both: string[] };
  blocked: { a: number; b: number };
  steps: { a: string[]; b: string[] };
}
