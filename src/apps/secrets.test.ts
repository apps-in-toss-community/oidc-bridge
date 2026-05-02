import { describe, expect, it } from 'vitest';
import {
  generateApiToken,
  generateClientSecret,
  hashApiToken,
  hashClientSecret,
  verifyApiToken,
  verifyClientSecret,
} from './secrets.js';

describe('client secret', () => {
  it('generates a 32-byte URL-safe random string', () => {
    const s = generateClientSecret();
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(s.length).toBeGreaterThan(40);
  });

  it('hashes and verifies a secret', async () => {
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    expect(hash.startsWith('$2')).toBe(true);
    expect(await verifyClientSecret(secret, [hash])).toBe(true);
  });

  it('verifies against any matching hash (rotation overlap)', async () => {
    const old = await hashClientSecret('old-secret');
    const fresh = await hashClientSecret('new-secret');
    expect(await verifyClientSecret('new-secret', [old, fresh])).toBe(true);
    expect(await verifyClientSecret('old-secret', [old, fresh])).toBe(true);
    expect(await verifyClientSecret('wrong', [old, fresh])).toBe(false);
  });

  it('returns false when the hash list is empty', async () => {
    expect(await verifyClientSecret('any', [])).toBe(false);
  });
});

describe('api token', () => {
  it('generates a token with `tok_` prefix', () => {
    const t = generateApiToken();
    expect(t.startsWith('tok_')).toBe(true);
    expect(t.length).toBeGreaterThan(40);
  });

  it('hashes deterministically (sha256)', () => {
    const t = 'tok_xxx';
    expect(hashApiToken(t)).toBe(hashApiToken(t));
    expect(hashApiToken(t)).not.toBe(hashApiToken('tok_yyy'));
    expect(hashApiToken(t)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('verifyApiToken matches generated tokens', () => {
    const t = generateApiToken();
    const h = hashApiToken(t);
    expect(verifyApiToken(t, h)).toBe(true);
    expect(verifyApiToken('tok_zzz', h)).toBe(false);
  });
});
