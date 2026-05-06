import { describe, expect, it } from 'vitest';
import { SlidingWindow } from './rate-limit.js';

describe('SlidingWindow', () => {
  it('admits up to limit within a window', () => {
    const now = 0;
    const sw = new SlidingWindow({ limit: 3, windowMs: 60_000, now: () => now });
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
  });

  it('separate keys are independent', () => {
    const now = 0;
    const sw = new SlidingWindow({ limit: 1, windowMs: 60_000, now: () => now });
    expect(sw.admit('a')).toBe(true);
    expect(sw.admit('b')).toBe(true);
    expect(sw.admit('a')).toBe(false);
    expect(sw.admit('b')).toBe(false);
  });

  it('window slides as time advances', () => {
    let now = 0;
    const sw = new SlidingWindow({ limit: 2, windowMs: 60_000, now: () => now });
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
    // Halfway into the next window — previous count weighted at 50%, current at 0%.
    // Effective = 2 * 0.5 + 0 = 1, room for 1 more.
    now = 90_000;
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
  });

  it('after two full windows, counters fully reset', () => {
    let now = 0;
    const sw = new SlidingWindow({ limit: 1, windowMs: 60_000, now: () => now });
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
    now = 130_000;
    expect(sw.admit('k')).toBe(true);
  });

  it('eventually evicts stale keys', () => {
    let now = 0;
    const sw = new SlidingWindow({ limit: 1, windowMs: 60_000, now: () => now });
    for (let i = 0; i < 999; i++) sw.admit(`k${i}`);
    // Two windows later, the existing 999 keys are sweep-eligible. The next
    // admit lands on op #1000, which triggers the sweep.
    now = 180_000;
    sw.admit('trigger-sweep');
    expect(sw.size()).toBeLessThan(999);
  });
});
