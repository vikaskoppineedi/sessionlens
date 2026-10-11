import { useEffect, useState } from 'react';
import { api } from '../api';
import { valueAt, type Selection } from '../state';
import type { Body, Headers, Model, RequestDetail, Row } from '../types';
import { buildCurl, charDiff, decodings, relTime, shortUrl } from '../util';

interface Props {
  session: string;
  model: Model;
  selection: Selection;
  reveal: boolean;
  onSelect: (s: Selection) => void;
  onClose: () => void;
}

export function Drawer({ session, model, selection, reveal, onSelect, onClose }: Props) {
  let content;
  if (selection.type === 'row') {
    const row = model.rows.find((r) => r.id === selection.rowId);
    content = row ? <RowPanel model={model} row={row} step={selection.step} onSelect={onSelect} /> : <p>Row no longer exists.</p>;
  } else if (selection.type === 'request') {
    content = <RequestPanel key={`${selection.id}-${reveal}`} session={session} id={selection.id} reveal={reveal} model={model} onSelect={onSelect} />;
  } else if (selection.type === 'disk') {
    const disk = model.disk.find((d) => d.kind === selection.kind);
    content = (
      <>
        <h2>
          {disk?.label} · step #{selection.step}
        </h2>
        <ItemTable items={disk?.cells[selection.step]?.items ?? []} />
      </>
    );
  } else {
    content = (
      <>
        <h2>Blocked cookies · step #{selection.step}</h2>
        <p className="muted">The server sent Set-Cookie, but the cookie jar didn't change. Reasons are inferred from the cookie's attributes.</p>
        {model.blocked
          .filter((b) => b.step === selection.step)
          .map((b, i) => (
            <div key={i} className="card">
              <b>{b.name}</b> — {b.reason}
              <pre>{b.raw}</pre>
              <button className="link" onClick={() => onSelect({ type: 'request', id: b.request })}>
                open request
              </button>
            </div>
          ))}
      </>
    );
  }
  return (
    <aside className="drawer">
      <button className="close" onClick={onClose} aria-label="close">
        ✕
      </button>
      {content}
    </aside>
  );
}

function ItemTable({ items }: { items: Record<string, unknown>[] }) {
  if (!items.length) return <p className="muted">Nothing here.</p>;
  const keys = [...new Set(items.flatMap((i) => Object.keys(i)))];
  return (
    <table className="kv">
      <thead>
        <tr>
          {keys.map((k) => (
            <th key={k}>{k}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {items.map((item, i) => (
          <tr key={i}>
            {keys.map((k) => (
              <td key={k}>{String(item[k] ?? '')}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RowPanel({ model, row, step, onSelect }: { model: Model; row: Row; step: number; onSelect: (s: Selection) => void }) {
  const value = valueAt(row, step);
  const previous = step > 0 ? valueAt(row, step - 1) : (row.initial ?? null);
  const t0 = model.steps[0]?.t ?? 0;
  const reqUrl = (id: string | null) => (id ? shortUrl(model.requests.find((r) => r.id === id)?.url ?? id) : '');
  const attrs = row.attrs ?? {};
  return (
    <>
      <h2>
        {row.name} <span className="muted">· step #{step}</span>
      </h2>
      <p className="muted">
        {row.group === 'cookie' ? `Cookie for ${row.domain}${row.path}` : row.section}
      </p>
      {row.group === 'cookie' ? (
        <div className="flags">
          {attrs.httpOnly ? <span className="flag">HttpOnly (JavaScript can't read it)</span> : <span className="flag">readable by JavaScript</span>}
          {attrs.secure ? <span className="flag">Secure (HTTPS only)</span> : null}
          <span className="flag">SameSite={String(attrs.sameSite ?? 'unspecified')}</span>
          <span className="flag">{attrs.session ? 'session cookie' : `expires ${attrs.expirationDate ? new Date(Number(attrs.expirationDate) * 1000).toLocaleString() : '?'}`}</span>
          {attrs.hostOnly ? <span className="flag">host-only</span> : <span className="flag">sent to subdomains too</span>}
          {row.persistence ? <span className="flag">{row.persistence.onDisk ? '💾 written to disk' : `not on disk: ${row.persistence.note}`}</span> : null}
        </div>
      ) : null}

      <h3>Value at end of this step</h3>
      {value === null ? <p className="muted">(not present)</p> : <pre className="value">{value}</pre>}
      {previous !== value ? (
        <>
          <h3>Change from previous step</h3>
          <pre className="value diff">
            {charDiff(previous, value).map((p, i) => (
              <span key={i} className={`d-${p.kind}`}>
                {p.text}
              </span>
            ))}
          </pre>
        </>
      ) : null}
      {value
        ? decodings(value).map((d) => (
            <div key={d.label}>
              <h3>{d.label}</h3>
              <pre className="value">{d.text}</pre>
            </div>
          ))
        : null}

      {row.group === 'cookie' ? (
        <>
          <h3>Where it came from</h3>
          {(row.setBy ?? []).length === 0 ? <p className="muted">Already present when capture started.</p> : null}
          <ul className="lineage">
            {(row.setBy ?? []).map((l, i) => (
              <li key={i}>
                step #{l.step} {relTime(l.t, t0)}: {l.source === 'header' ? 'Set-Cookie header from ' : l.source === 'javascript' ? 'set by page JavaScript (document.cookie)' : l.source}
                <RequestLink id={l.request} label={reqUrl(l.request)} onSelect={onSelect} />
              </li>
            ))}
            {(row.removedBy ?? []).map((l, i) => (
              <li key={`r${i}`}>
                step #{l.step}: removed ({l.cause}) {l.request ? <RequestLink id={l.request} label={reqUrl(l.request)} onSelect={onSelect} /> : l.source}
              </li>
            ))}
          </ul>
          <h3>Sent with {row.sentBy?.length ?? 0} requests</h3>
          <ul className="lineage">
            {(row.sentBy ?? []).slice(0, 50).map((id) => (
              <li key={id}>
                <button className="link" onClick={() => onSelect({ type: 'request', id })}>
                  {reqUrl(id)}
                </button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </>
  );
}

function RequestLink({ id, label, onSelect }: { id: string | null; label: string; onSelect: (s: Selection) => void }) {
  if (!id) return null;
  return (
    <button className="link" onClick={() => onSelect({ type: 'request', id })}>
      {label}
    </button>
  );
}

function HeaderTable({ headers, highlight }: { headers: Headers; highlight?: string[] }) {
  return (
    <table className="kv">
      <tbody>
        {headers.map(([n, v], i) => (
          <tr key={i} className={highlight?.includes(n.toLowerCase()) ? 'hl' : ''}>
            <th>{n}</th>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function BodyView({ body }: { body: Body }) {
  switch (body.kind) {
    case 'none':
      return <p className="muted">No body.</p>;
    case 'form':
      return <HeaderTable headers={body.form ?? []} />;
    case 'json':
      return <pre className="value">{JSON.stringify(body.json, null, 2)}</pre>;
    case 'text':
      return <pre className="value">{body.text}{body.truncated ? '\n… (truncated)' : ''}</pre>;
    case 'binary':
      return <pre className="value">binary, {body.size} bytes{'\n'}{body.hexPreview}</pre>;
    case 'skipped':
      return <p className="muted">Media body not stored ({body.size} bytes).</p>;
    default:
      return <p className="muted">Not available: {body.reason}</p>;
  }
}

function RequestPanel({ session, id, reveal, model, onSelect }: { session: string; id: string; reveal: boolean; model: Model; onSelect: (s: Selection) => void }) {
  const [detail, setDetail] = useState<RequestDetail | null>(null);
  const [error, setError] = useState('');
  const [showExt, setShowExt] = useState(false);
  const [unsafeOk, setUnsafeOk] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .detail(session, id, reveal)
      .then((d) => !cancelled && setDetail(d))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [session, id, reveal]);

  if (error) return <p className="error">{error}</p>;
  if (!detail) return <p className="muted">Loading…</p>;

  const reqHeaders = (showExt ? detail.requestHeaders.ext : detail.requestHeaders.wire) ?? detail.requestHeaders.ext ?? [];
  const respHeaders = (showExt ? detail.responseHeaders.ext : detail.responseHeaders.wire) ?? detail.responseHeaders.ext ?? [];
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(detail.method);
  const run = async (fn: () => Promise<Record<string, unknown>>) => {
    setBusy(true);
    try {
      setResult(await fn());
    } catch (e) {
      setResult({ error: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const rowName = (rowId: string | null) => model.rows.find((r) => r.id === rowId)?.name ?? rowId;

  return (
    <>
      <h2 className="req-title">
        <span className="m">{detail.method}</span> {detail.url}
      </h2>
      <div className="flags">
        <span className="flag">status {detail.status ?? '—'}</span>
        <span className="flag">step #{detail.step}</span>
        {detail.proto ? <span className="flag">{detail.proto}</span> : null}
        <span className="flag">{detail.match}</span>
        {detail.resourceType ? <span className="flag">{detail.resourceType}</span> : null}
        {detail.initiator ? <span className="flag">from {detail.initiator}</span> : null}
        {detail.redirectTo ? <span className="flag">→ redirects to {shortUrl(detail.redirectTo)}</span> : null}
        {detail.error ? <span className="flag err">{detail.error}</span> : null}
      </div>

      <div className="actions">
        <button onClick={() => navigator.clipboard.writeText(buildCurl(detail))}>Copy as cURL</button>
        <button disabled={busy || (unsafe && !unsafeOk)} onClick={() => run(() => api.replay(session, id, { allowUnsafe: unsafeOk }))}>
          Replay
        </button>
        <button disabled={busy || (unsafe && !unsafeOk)} onClick={() => run(() => api.minimize(session, id, unsafeOk))} title="Remove headers and cookies one by one to find what the server really checks">
          Replay + minimize
        </button>
        {unsafe ? (
          <label className="warn">
            <input type="checkbox" checked={unsafeOk} onChange={(e) => setUnsafeOk(e.target.checked)} /> I understand replaying {detail.method} may repeat the action
          </label>
        ) : null}
      </div>
      <p className="muted small">Replays go from Python on your Mac, with your captured cookies. Bot protection may treat them differently from Chrome.</p>
      {busy ? <p className="muted">Replaying…</p> : null}
      {result ? <pre className="value">{JSON.stringify(result, null, 2)}</pre> : null}

      {detail.query.length ? (
        <>
          <h3>Query parameters</h3>
          <HeaderTable headers={detail.query} />
        </>
      ) : null}

      <h3>
        Request headers{' '}
        {detail.requestHeaders.wire && detail.requestHeaders.ext ? (
          <button className="link" onClick={() => setShowExt(!showExt)}>
            showing {showExt ? 'extension view' : 'exact wire bytes'} (switch)
          </button>
        ) : null}
      </h3>
      <HeaderTable headers={reqHeaders} highlight={['cookie', 'authorization', 'x-csrf-token', 'x-xsrf-token']} />

      {detail.cookiesSentValues.length ? (
        <>
          <h3>Cookies sent</h3>
          <div className="chips">
            {detail.cookiesSentValues.map((c, i) => {
              const rowId = detail.cookiesSent.find((r) => r.endsWith(`|${c.name}`));
              return (
                <button key={i} className="chip" onClick={() => rowId && onSelect({ type: 'row', rowId, step: detail.step })} title={c.value}>
                  {c.name}
                </button>
              );
            })}
          </div>
        </>
      ) : null}

      <h3>Request body</h3>
      <BodyView body={detail.requestBody} />

      <h3>Response headers</h3>
      <HeaderTable headers={respHeaders} highlight={['set-cookie', 'location', 'content-type']} />

      {detail.cookiesSet.length ? (
        <>
          <h3>Set-Cookie outcomes</h3>
          <table className="kv">
            <tbody>
              {detail.cookiesSet.map(({ rowId, ...c }, i) => (
                <tr key={i} className={`out-${c.outcome}`}>
                  <th>{c.name}</th>
                  <td>
                    <b>{c.outcome}</b>
                    {c.reason ? ` — ${c.reason}` : ''}
                    {rowId ? (
                      <button className="link" onClick={() => onSelect({ type: 'row', rowId, step: detail.step })}>
                        {rowName(rowId)} row
                      </button>
                    ) : null}
                    <div className="muted small">{c.raw}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      <h3>Response body</h3>
      {detail.responseBody.decodeError ? <p className="error">{detail.responseBody.decodeError}</p> : null}
      <BodyView body={detail.responseBody} />
    </>
  );
}
