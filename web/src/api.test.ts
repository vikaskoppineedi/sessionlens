import { describe, expect, it } from 'vitest';
import { parseEmbedded } from './api';

describe('parseEmbedded', () => {
  it('returns the report data from valid JSON', () => {
    const data = { session: 's1', model: { live: false }, details: {}, screenshots: { '0': 'screenshots/step-00.jpg' } };
    expect(parseEmbedded(JSON.stringify(data))).toEqual(data);
  });

  it('returns null when there is no blob', () => {
    expect(parseEmbedded(null)).toBeNull();
    expect(parseEmbedded('')).toBeNull();
  });

  it('returns null for invalid or unrelated JSON', () => {
    expect(parseEmbedded('{not json')).toBeNull();
    expect(parseEmbedded('null')).toBeNull();
    expect(parseEmbedded('[1, 2]')).toBeNull();
  });
});
