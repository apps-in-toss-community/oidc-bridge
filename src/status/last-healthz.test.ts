import { describe, expect, it } from 'vitest';
import { getLastHealthz, recordHealthz, resetLastHealthz } from './last-healthz.js';

describe('last-healthz', () => {
  it('starts as null after reset', () => {
    resetLastHealthz();
    expect(getLastHealthz()).toBeNull();
  });

  it('records and returns most recent timestamp', () => {
    resetLastHealthz();
    recordHealthz(new Date('2026-05-01T00:00:00Z'));
    expect(getLastHealthz()?.toISOString()).toBe('2026-05-01T00:00:00.000Z');
    recordHealthz(new Date('2026-05-01T00:01:00Z'));
    expect(getLastHealthz()?.toISOString()).toBe('2026-05-01T00:01:00.000Z');
  });

  it('default arg uses now()', () => {
    resetLastHealthz();
    const before = Date.now();
    recordHealthz();
    const after = Date.now();
    const t = getLastHealthz();
    expect(t).not.toBeNull();
    expect(t!.getTime()).toBeGreaterThanOrEqual(before);
    expect(t!.getTime()).toBeLessThanOrEqual(after);
  });
});
