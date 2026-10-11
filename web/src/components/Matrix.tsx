import { useMemo, useState } from 'react';
import { api } from '../api';
import { groupBySection, requestsForRow, visibleRows, type Filters, type Selection } from '../state';
import type { Cell, Model, RequestSummary, Row, Step } from '../types';
import { relTime } from '../util';

interface Props {
  session: string;
  model: Model;
  filters: Filters;
  selectedStep: number | null;
  onSelect: (s: Selection) => void;
  onSelectStep: (step: number) => void;
}

const LANE_LIMIT = 12;
const ICON: Record<Step['kind'], string> = { start: '🚀', action: '👆', nav: '🧭', spa: '↪️' };
const MATCH_ICON: Record<RequestSummary['match'], string> = { matched: '🌐', 'ext-only': '🧩', 'wire-only': '📡', ambiguous: '❓', cache: '💾' };
const MATCH_HELP: Record<RequestSummary['match'], string> = {
  matched: 'seen by extension and on the wire',
  'ext-only': 'seen by extension only (wire copy not found)',
  'wire-only': 'seen on the wire only (Chrome background, service worker, or another app)',
  ambiguous: 'matched to the wire, but several identical requests were close together',
  cache: 'served from cache: never hit the network',
};

function truncate(value: string | null | undefined, n = 16): string {
  const v = value ?? '';
  return v.length > n ? `${v.slice(0, n)}…` : v;
}

function cellText(cell: Cell): string {
  switch (cell.state) {
    case 'added':
      return `+ ${truncate(cell.value)}`;
    case 'changed':
      return `~ ${truncate(cell.value)}`;
    case 'removed':
      return '✕ gone';
    case 'same':
      return cell.touched ? '• same' : '·';
    default:
      return cell.touched ? '•' : '';
  }
}

function statusClass(status: number | null): string {
  if (status === null) return 'st-none';
  if (status >= 400) return 'st-err';
  if (status >= 300) return 'st-redirect';
  return 'st-ok';
}

function path(url: string): string {
  try {
    const u = new URL(url);
    return `${u.pathname}${u.search}`;
  } catch {
    return url;
  }
}

function host(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

export function Matrix({ session, model, filters, selectedStep, onSelect, onSelectStep }: Props) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [expandedLane, setExpandedLane] = useState<Set<number>>(new Set());
  const [hoverRow, setHoverRow] = useState<Row | null>(null);
  const [hoverRequest, setHoverRequest] = useState<RequestSummary | null>(null);

  const rows = useMemo(() => visibleRows(model, filters), [model, filters]);
  const sections = useMemo(() => groupBySection(rows), [rows]);
  const t0 = model.steps[0]?.t ?? 0;
  const q = filters.search.trim().toLowerCase();
  // Only what the browser did: wire-only traffic (other apps, Chrome background) is never shown.
  const requests = model.requests.filter((r) => r.match !== 'wire-only' && (!q || r.url.toLowerCase().includes(q)));
  const requestLinks = hoverRow ? requestsForRow(hoverRow) : null;
  const rowLinks = new Map<string, 'sent' | 'set'>();
  if (hoverRequest) {
    for (const id of hoverRequest.cookiesSent) rowLinks.set(id, 'sent');
    for (const id of hoverRequest.cookiesSet) rowLinks.set(id, 'set');
  }
  const blockedByStep = model.steps.map((s) => model.blocked.filter((b) => b.step === s.id).length);
  const colClass = (i: number) => (selectedStep === i ? 'col-selected' : '');

  const toggle = <T,>(set: Set<T>, value: T, update: (s: Set<T>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    update(next);
  };

  return (
    <div className="matrix-wrap">
      <table className="matrix">
        <thead>
          <tr>
            <th className="corner">
              {rows.length} rows · {requests.length} requests
            </th>
            {model.steps.map((s, i) => (
              <th key={s.id} id={`step-col-${s.id}`} className={`step-head ${colClass(i)}`} title={s.url ?? ''} onClick={() => onSelectStep(s.id)}>
                {s.screenshot !== null ? <img src={api.screenshotUrl(session, s.screenshot)} alt="" loading="lazy" /> : <div className="no-shot">{ICON[s.kind]}</div>}
                <div>
                  #{s.id} {truncate(s.label, 28)}
                </div>
                <small>{relTime(s.t, t0)}</small>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sections.map(([title, sectionRows]) => {
            const changed = sectionRows.filter((r) => r.cells.some((c) => c.state !== 'same' && c.state !== 'absent')).length;
            const isCollapsed = collapsed.has(title);
            return [
              <tr key={`s-${title}`} className="section-row" onClick={() => toggle(collapsed, title, setCollapsed)}>
                <th className="sticky-col">
                  {isCollapsed ? '▶' : '▼'} {title} <span className="muted">({sectionRows.length}, {changed} changed)</span>
                </th>
                <td colSpan={model.steps.length} />
              </tr>,
              ...(isCollapsed
                ? []
                : sectionRows.map((row) => (
                    <tr key={row.id} className={rowLinks.has(row.id) ? `linked-${rowLinks.get(row.id)}` : ''}>
                      <th className="sticky-col row-name" onMouseEnter={() => setHoverRow(row)} onMouseLeave={() => setHoverRow(null)} title={row.id}>
                        <span className="name">{row.name}</span>
                        {row.domain?.startsWith('.') ? <span className="flag" title={`Domain cookie: also sent to subdomains of ${row.domain.slice(1)}`}>+subdomains</span> : null}
                        {row.path && row.path !== '/' ? <span className="flag">path {row.path}</span> : null}
                        {row.attrs?.httpOnly ? <span className="flag">HttpOnly</span> : null}
                        {row.persistence?.onDisk ? <span className="flag disk">💾</span> : null}
                        {row.badges.map((b) => (
                          <span key={b} className={`badge b-${b}`}>
                            {b}
                          </span>
                        ))}
                      </th>
                      {row.cells.map((cell, i) => (
                        <td key={i} className={`cell ${cell.state} ${colClass(i)}`} onClick={() => onSelect({ type: 'row', rowId: row.id, step: i })} title={cell.value ?? undefined}>
                          {cellText(cell)}
                        </td>
                      ))}
                    </tr>
                  ))),
            ];
          })}

          <tr className="section-row">
            <th className="sticky-col">▼ Requests</th>
            <td colSpan={model.steps.length} />
          </tr>
          <tr className="lane">
            <th className="sticky-col row-name">
              by step <span className="muted">(🌐 wire+ext 🧩 ext only 💾 cache)</span>
            </th>
            {model.steps.map((s, i) => {
              const inStep = requests.filter((r) => r.step === s.id);
              const shown = expandedLane.has(s.id) ? inStep : inStep.slice(0, LANE_LIMIT);
              return (
                <td key={s.id} className={`lane-cell ${colClass(i)}`}>
                  {shown.map((r) => (
                    <div
                      key={r.id}
                      className={`req ${requestLinks?.has(r.id) ? `linked-${requestLinks.get(r.id)}` : ''}`}
                      onClick={() => onSelect({ type: 'request', id: r.id })}
                      onMouseEnter={() => setHoverRequest(r)}
                      onMouseLeave={() => setHoverRequest(null)}
                      title={`${r.method} ${r.url}\n${MATCH_HELP[r.match]}`}
                    >
                      <span className="m">{r.method}</span>
                      <span className={`st ${statusClass(r.status)}`}>{r.status ?? '…'}</span>
                      <span className="p">{path(r.url)}</span>
                      <span className="h">{host(r.url)}</span>
                      <span className="mi">{MATCH_ICON[r.match]}</span>
                      {r.blocked ? <span className="blk">🚫{r.blocked}</span> : null}
                    </div>
                  ))}
                  {inStep.length > LANE_LIMIT ? (
                    <button className="more" onClick={() => toggle(expandedLane, s.id, setExpandedLane)}>
                      {expandedLane.has(s.id) ? 'show less' : `+${inStep.length - LANE_LIMIT} more`}
                    </button>
                  ) : null}
                </td>
              );
            })}
          </tr>
          <tr>
            <th className="sticky-col row-name">Blocked cookies 🚫</th>
            {blockedByStep.map((n, i) => (
              <td key={i} className={`cell ${n ? 'removed' : ''} ${colClass(i)}`} onClick={() => n && onSelect({ type: 'blocked', step: i })}>
                {n || ''}
              </td>
            ))}
          </tr>

          {model.disk.length ? (
            <tr className="section-row">
              <th className="sticky-col">
                ▼ Disk only <span className="muted">(what Chrome wrote to the profile folder)</span>
              </th>
              <td colSpan={model.steps.length} />
            </tr>
          ) : null}
          {model.disk.map((d) => (
            <tr key={d.kind}>
              <th className="sticky-col row-name">{d.label}</th>
              {d.cells.map((c, i) => (
                <td key={i} className={`cell ${c.count ? 'disk-cell' : ''} ${colClass(i)}`} onClick={() => c.count && onSelect({ type: 'disk', kind: d.kind, step: i })}>
                  {c.count || ''}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
