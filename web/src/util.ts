import { diffChars } from 'diff';
import type { RequestDetail } from './types';

function base64UrlDecode(part: string): string {
  const padded = part.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(part.length / 4) * 4, '=');
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function decodeJwt(value: string): { header: unknown; payload: unknown } | null {
  const parts = value.split('.');
  if (parts.length !== 3 || !parts[0].startsWith('eyJ')) return null;
  try {
    return { header: JSON.parse(base64UrlDecode(parts[0])), payload: JSON.parse(base64UrlDecode(parts[1])) };
  } catch {
    return null;
  }
}

// No control characters except tab / newline / carriage return.
// eslint-disable-next-line no-control-regex
const PRINTABLE = /^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$/;

/** Ways a cookie/token value can be made readable. */
export function decodings(value: string): { label: string; text: string }[] {
  const out: { label: string; text: string }[] = [];
  if (!value) return out;
  try {
    const decoded = decodeURIComponent(value);
    if (decoded !== value) out.push({ label: 'URL-decoded', text: decoded });
  } catch {
    // not valid percent-encoding
  }
  const jwt = decodeJwt(value);
  if (jwt) {
    out.push({ label: 'JWT header', text: JSON.stringify(jwt.header, null, 2) });
    out.push({ label: 'JWT payload', text: JSON.stringify(jwt.payload, null, 2) });
  } else if (value.length >= 8 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) {
    try {
      const text = base64UrlDecode(value.replace(/=+$/, ''));
      if (PRINTABLE.test(text)) out.push({ label: 'Base64', text });
    } catch {
      // not base64 text
    }
  }
  return out;
}

const TRACKERS = [/^_ga(_|$)/, /^_gid$/, /^_gat/, /^_gcl_/, /^_fbp$/, /^_fbc$/, /^__utm/, /^_hj/, /^ajs_/, /^_uet/, /^_clck$/, /^_clsk$/, /^mp_/, /^amplitude_/];

export function isTracker(name: string): boolean {
  return TRACKERS.some((re) => re.test(name));
}

const SKIP_CURL_HEADERS = new Set(['content-length', 'host', 'connection', 'accept-encoding']);

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function buildCurl(detail: RequestDetail): string {
  const headers = detail.requestHeaders.wire ?? detail.requestHeaders.ext ?? [];
  const parts = [detail.method === 'GET' ? `curl ${shellQuote(detail.url)}` : `curl -X ${detail.method} ${shellQuote(detail.url)}`];
  for (const [name, value] of headers) {
    if (!SKIP_CURL_HEADERS.has(name.toLowerCase())) parts.push(`-H ${shellQuote(`${name}: ${value}`)}`);
  }
  const body = detail.requestBody;
  let data: string | null = null;
  if (body.kind === 'form' && body.form) data = body.form.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
  else if (body.kind === 'json') data = JSON.stringify(body.json);
  else if (body.kind === 'text' && body.text) data = body.text;
  if (data !== null) parts.push(`--data-raw ${shellQuote(data)}`);
  return parts.join(' \\\n  ');
}

export interface DiffPart {
  text: string;
  kind: 'same' | 'added' | 'removed';
}

export function charDiff(before: string | null | undefined, after: string | null | undefined): DiffPart[] {
  return diffChars(before ?? '', after ?? '').map((p) => ({ text: p.value, kind: p.added ? 'added' : p.removed ? 'removed' : 'same' }));
}

export function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}${u.search}`;
  } catch {
    return url;
  }
}

export function relTime(t: number, start: number): string {
  return `+${(Math.max(0, t - start) / 1000).toFixed(1)}s`;
}
