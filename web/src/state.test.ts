import { describe, expect, it } from 'vitest';
import { groupBySection, requestsForRow, rowChanged, valueAt, visibleRows } from './state';
import type { Model, Row } from './types';

const row = (over: Partial<Row>): Row => ({
  id: 'c|x|/|a', group: 'cookie', section: 'x.com', name: 'a', badges: [], cells: [], ...over,
});

describe('valueAt', () => {
  const cells = [{ state: 'absent' }, { state: 'added', value: 'v1' }, { state: 'same' }, { state: 'changed', value: 'v2' }, { state: 'removed' }] as Row['cells'];
  it('rebuilds the value at each step', () => {
    expect([0, 1, 2, 3, 4].map((s) => valueAt({ cells }, s))).toEqual([null, 'v1', 'v1', 'v2', null]);
  });
  it('starts from the value at capture start', () => {
    expect(valueAt({ cells: [{ state: 'same' }], initial: 'base' }, 0)).toBe('base');
  });
});

describe('rowChanged', () => {
  it('ignores rows that never changed', () => {
    expect(rowChanged(row({ cells: [{ state: 'same' }, { state: 'same' }] }))).toBe(false);
    expect(rowChanged(row({ cells: [{ state: 'absent' }, { state: 'added', value: 'x' }] }))).toBe(true);
    expect(rowChanged(row({ cells: [{ state: 'same' }, { state: 'same', touched: true }] }))).toBe(true);
  });
});

describe('visibleRows', () => {
  const model = {
    rows: [
      row({ id: '1', name: '_ga', cells: [{ state: 'added', value: 'GA1' }] }),
      row({ id: '2', name: 'sid', cells: [{ state: 'same' }] }),
      row({ id: '3', name: 'token', group: 'local', section: 'Local Storage · https://x.com', cells: [{ state: 'added', value: 'eyJabc' }] }),
    ],
  } as unknown as Model;
  const base = { changedOnly: false, hideTrackers: false, search: '' };

  it('hides trackers', () => {
    expect(visibleRows(model, { ...base, hideTrackers: true }).map((r) => r.id)).toEqual(['2', '3']);
  });
  it('shows changed only', () => {
    expect(visibleRows(model, { ...base, changedOnly: true }).map((r) => r.id)).toEqual(['1', '3']);
  });
  it('searches names and values', () => {
    expect(visibleRows(model, { ...base, search: 'EYJ' }).map((r) => r.id)).toEqual(['3']);
  });
});

describe('grouping and links', () => {
  it('groups cookies by domain and storage by section', () => {
    const groups = groupBySection([row({ id: '1' }), row({ id: '2', group: 'local', section: 'Local Storage · o' })]);
    expect(groups.map(([title]) => title)).toEqual(['Cookies · x.com', 'Local Storage · o']);
  });
  it('maps requests that sent or set a cookie', () => {
    const links = requestsForRow(row({ sentBy: ['r1'], setBy: [{ t: 0, step: 1, source: 'header', request: 'r2' }], removedBy: [] }));
    expect([...links]).toEqual([['r1', 'sent'], ['r2', 'set']]);
  });
});
