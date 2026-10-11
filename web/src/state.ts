import type { Cell, Model, Row } from './types';
import { isTracker } from './util';

export type Selection =
  | { type: 'row'; rowId: string; step: number }
  | { type: 'request'; id: string }
  | { type: 'disk'; kind: string; step: number }
  | { type: 'blocked'; step: number };

export interface Filters {
  changedOnly: boolean;
  hideTrackers: boolean;
  search: string;
}

/** Value of a row at the end of a step, rebuilt from its value at capture start plus per-step cells. */
export function valueAt(row: Pick<Row, 'cells' | 'initial'>, step: number): string | null {
  let value: string | null = row.initial ?? null;
  for (let i = 0; i <= step && i < row.cells.length; i++) {
    const cell: Cell = row.cells[i];
    if (cell.state === 'added' || cell.state === 'changed') value = cell.value ?? '';
    else if (cell.state === 'removed') value = null;
  }
  return value;
}

export function rowChanged(row: Row): boolean {
  return row.cells.some((c) => (c.state !== 'same' && c.state !== 'absent') || c.touched);
}

export function visibleRows(model: Model, filters: Filters): Row[] {
  const q = filters.search.trim().toLowerCase();
  return model.rows.filter((row) => {
    if (filters.hideTrackers && row.group === 'cookie' && isTracker(row.name)) return false;
    if (filters.changedOnly && !rowChanged(row)) return false;
    if (!q) return true;
    return (
      row.name.toLowerCase().includes(q) ||
      row.section.toLowerCase().includes(q) ||
      row.cells.some((c) => (c.value ?? '').toLowerCase().includes(q))
    );
  });
}

export function groupBySection(rows: Row[]): [string, Row[]][] {
  const groups = new Map<string, Row[]>();
  for (const row of rows) {
    const title = row.group === 'cookie' ? `Cookies · ${row.section}` : row.section;
    groups.set(title, [...(groups.get(title) ?? []), row]);
  }
  return [...groups.entries()];
}

/** Hover links: which requests touch a row, and which rows a request touched. */
export function requestsForRow(row: Row): Map<string, 'sent' | 'set'> {
  const out = new Map<string, 'sent' | 'set'>();
  for (const id of row.sentBy ?? []) out.set(id, 'sent');
  for (const l of [...(row.setBy ?? []), ...(row.removedBy ?? [])]) if (l.request) out.set(l.request, 'set');
  return out;
}
