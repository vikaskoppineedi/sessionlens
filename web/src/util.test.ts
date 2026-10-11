import { describe, expect, it } from 'vitest';
import type { RequestDetail } from './types';
import { buildCurl, charDiff, decodings, decodeJwt, isTracker, relTime, shortUrl } from './util';

const b64url = (s: string) =>
  btoa(String.fromCharCode(...new TextEncoder().encode(s)))
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

describe('decodeJwt', () => {
  it('decodes header and payload', () => {
    const token = `${b64url('{"alg":"HS256"}')}.${b64url('{"sub":"демо","exp":1}')}.sig`;
    expect(decodeJwt(token)).toEqual({ header: { alg: 'HS256' }, payload: { sub: 'демо', exp: 1 } });
  });
  it('returns null for non-JWT values', () => {
    expect(decodeJwt('abc')).toBeNull();
    expect(decodeJwt('a.b.c')).toBeNull();
    expect(decodeJwt('')).toBeNull();
  });
});

describe('decodings', () => {
  it('url-decodes when it changes the value', () => {
    expect(decodings('a%20b%3D')).toContainEqual({ label: 'URL-decoded', text: 'a b=' });
  });
  it('base64-decodes printable text only', () => {
    expect(decodings(btoa('hello world'))).toContainEqual({ label: 'Base64', text: 'hello world' });
    expect(decodings('abcd').find((d) => d.label === 'Base64')).toBeUndefined();
  });
  it('shows JWT parts', () => {
    const token = `${b64url('{"alg":"none"}')}.${b64url('{"a":1}')}.x`;
    expect(decodings(token).map((d) => d.label)).toContain('JWT payload');
  });
  it('handles empty and malformed input', () => {
    expect(decodings('')).toEqual([]);
    expect(() => decodings('%E0%A4%A')).not.toThrow();
  });
});

describe('isTracker', () => {
  it('flags common analytics cookies', () => {
    for (const name of ['_ga', '_ga_ABC123', '_gid', '_fbp', '__utma', '_hjSession_1', 'ajs_user_id', '_gcl_au']) {
      expect(isTracker(name)).toBe(true);
    }
  });
  it('leaves app cookies alone', () => {
    for (const name of ['sessionid', 'csrftoken', '__cf_bm', 'cf_clearance', 'gaming']) {
      expect(isTracker(name)).toBe(false);
    }
  });
});

describe('buildCurl', () => {
  const detail = {
    method: 'POST',
    url: "https://x.com/login?next=/a'b",
    requestHeaders: { wire: [['cookie', 'sid=1'], ['content-type', 'application/x-www-form-urlencoded'], ['content-length', '9']], ext: null },
    requestBody: { kind: 'form', form: [['user', 'demo'], ['pw', 'x y']] },
  } as unknown as RequestDetail;

  it('includes method, quoted url, headers and body', () => {
    const curl = buildCurl(detail);
    expect(curl).toContain("curl -X POST 'https://x.com/login?next=/a'\\''b'");
    expect(curl).toContain("-H 'cookie: sid=1'");
    expect(curl).not.toContain('content-length');
    expect(curl).toContain("--data-raw 'user=demo&pw=x%20y'");
  });

  it('falls back to extension headers and omits empty bodies', () => {
    const get = { method: 'GET', url: 'https://x.com/', requestHeaders: { wire: null, ext: [['Accept', '*/*']] }, requestBody: { kind: 'none' } } as unknown as RequestDetail;
    expect(buildCurl(get)).toBe("curl 'https://x.com/' \\\n  -H 'Accept: */*'");
  });

  it('serialises JSON bodies', () => {
    const post = { method: 'POST', url: 'https://x.com/', requestHeaders: { wire: [], ext: null }, requestBody: { kind: 'json', json: { a: 1 } } } as unknown as RequestDetail;
    expect(buildCurl(post)).toContain(`--data-raw '{"a":1}'`);
  });
});

describe('charDiff', () => {
  it('marks added and removed characters', () => {
    expect(charDiff('abc', 'abd')).toEqual([
      { text: 'ab', kind: 'same' },
      { text: 'c', kind: 'removed' },
      { text: 'd', kind: 'added' },
    ]);
  });
  it('handles missing previous value', () => {
    expect(charDiff(null, 'x')).toEqual([{ text: 'x', kind: 'added' }]);
  });
});

describe('formatting', () => {
  it('shortens urls', () => {
    expect(shortUrl('https://www.example.com/a/b?c=1')).toBe('www.example.com/a/b?c=1');
    expect(shortUrl('not a url')).toBe('not a url');
  });
  it('shows time relative to session start', () => {
    expect(relTime(12_345, 0)).toBe('+12.3s');
    expect(relTime(5, 10)).toBe('+0.0s');
  });
});
