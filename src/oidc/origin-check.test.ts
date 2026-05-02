import { describe, expect, it } from 'vitest';
import { originIsAllowed } from './origin-check.js';

describe('originIsAllowed', () => {
  it('strict equality on allowed list', () => {
    expect(originIsAllowed('https://app.example.com', ['https://app.example.com'])).toBe(true);
    expect(originIsAllowed('https://APP.example.com', ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('https://app.example.com/', ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('https://evil.example.com', ['https://app.example.com'])).toBe(false);
  });

  it('returns false for missing origin', () => {
    expect(originIsAllowed(undefined, ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('', ['https://app.example.com'])).toBe(false);
  });

  it('returns false for empty allowlist (default deny)', () => {
    expect(originIsAllowed('https://app.example.com', [])).toBe(false);
  });

  it('rejects literal "null" origin', () => {
    expect(originIsAllowed('null', ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('null', ['null'])).toBe(false);
  });

  it('rejects origin with surrounding whitespace', () => {
    expect(originIsAllowed(' https://app.example.com', ['https://app.example.com'])).toBe(false);
    expect(originIsAllowed('https://app.example.com ', ['https://app.example.com'])).toBe(false);
  });

  it('rejects bogus allowlist entries (empty / null literal)', () => {
    expect(originIsAllowed('', [''])).toBe(false);
    expect(originIsAllowed('null', ['null'])).toBe(false);
  });
});
