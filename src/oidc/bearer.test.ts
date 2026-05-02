import { describe, expect, it } from 'vitest';
import { parseBearer } from './bearer.js';

describe('parseBearer', () => {
  it('extracts the token from Bearer scheme', () => {
    expect(parseBearer('Bearer ait_abc')).toBe('ait_abc');
    expect(parseBearer('bearer ait_abc')).toBe('ait_abc');
  });

  it('returns null for missing or wrong scheme', () => {
    expect(parseBearer(undefined)).toBe(null);
    expect(parseBearer('')).toBe(null);
    expect(parseBearer('Basic abcd')).toBe(null);
    expect(parseBearer('Bearer')).toBe(null);
    expect(parseBearer('Bearer  ')).toBe(null);
  });
});
