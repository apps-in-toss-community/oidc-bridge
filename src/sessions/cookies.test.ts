import { describe, expect, it } from 'vitest';
import { clearSessionCookie, readSessionCookie, setSessionCookie } from './cookies.js';

describe('setSessionCookie', () => {
  it('produces __Host- cookie with HttpOnly Secure SameSite=Lax Path=/', () => {
    const v = setSessionCookie('abc123', new Date('2030-01-01T00:00:00Z'));
    expect(v).toContain('__Host-bridge_session=abc123');
    expect(v).toContain('Path=/');
    expect(v).toContain('HttpOnly');
    expect(v).toContain('Secure');
    expect(v).toContain('SameSite=Lax');
    expect(v).toContain('Expires=Tue, 01 Jan 2030 00:00:00 GMT');
    expect(v).not.toContain('Domain=');
  });
});

describe('clearSessionCookie', () => {
  it('produces a Max-Age=0 same-shape cookie', () => {
    const v = clearSessionCookie();
    expect(v).toContain('__Host-bridge_session=');
    expect(v).toContain('Max-Age=0');
    expect(v).toContain('HttpOnly');
    expect(v).toContain('Secure');
    expect(v).toContain('SameSite=Lax');
    expect(v).toContain('Path=/');
    expect(v).not.toContain('Domain=');
  });
});

describe('readSessionCookie', () => {
  it('returns the session id when present amongst other cookies', () => {
    const header = 'foo=bar; __Host-bridge_session=abc123; baz=qux';
    expect(readSessionCookie(header)).toBe('abc123');
  });

  it('returns null when not present', () => {
    expect(readSessionCookie('foo=bar; baz=qux')).toBeNull();
  });

  it('returns null when header is null/undefined/empty', () => {
    expect(readSessionCookie(null)).toBeNull();
    expect(readSessionCookie(undefined)).toBeNull();
    expect(readSessionCookie('')).toBeNull();
  });

  it('returns null when value is empty', () => {
    expect(readSessionCookie('__Host-bridge_session=')).toBeNull();
  });
});
