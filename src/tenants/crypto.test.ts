import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  certFingerprintSha256,
  certNotAfterUnix,
  generateClientSecret,
  generateTenantId,
  hashClientSecret,
  verifyClientSecret,
} from './crypto.js';

describe('generateTenantId', () => {
  it('returns "tnt_" + 24 Crockford b32 chars', () => {
    const id = generateTenantId();
    expect(id).toMatch(/^tnt_[0-9a-hjkmnp-tv-z]{24}$/);
  });

  it('is collision-resistant across 1000 generations', () => {
    const ids = new Set(Array.from({ length: 1000 }, () => generateTenantId()));
    expect(ids.size).toBe(1000);
  });
});

describe('generateClientSecret', () => {
  it('returns 43-char base64url string', () => {
    const s = generateClientSecret();
    expect(s).toHaveLength(43);
    expect(s).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('hashClientSecret + verifyClientSecret', () => {
  it('round-trips with bcrypt cost 12', async () => {
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    expect(hash).toMatch(/^\$2[aby]\$12\$/);
    expect(await verifyClientSecret(secret, hash)).toBe(true);
    expect(await verifyClientSecret('wrong', hash)).toBe(false);
  });

  it('verifies against any of multiple hashes (rotation overlap)', async () => {
    const oldSecret = generateClientSecret();
    const newSecret = generateClientSecret();
    const oldHash = await hashClientSecret(oldSecret);
    const newHash = await hashClientSecret(newSecret);
    expect(await verifyClientSecret(oldSecret, [newHash, oldHash])).toBe(true);
    expect(await verifyClientSecret(newSecret, [newHash, oldHash])).toBe(true);
    expect(await verifyClientSecret('neither', [newHash, oldHash])).toBe(false);
  });
});

describe('certFingerprintSha256', () => {
  it('returns lowercase hex SHA-256 of DER form', () => {
    const pem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
    const fp = certFingerprintSha256(pem);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('certNotAfterUnix', () => {
  it('parses NotAfter into unix seconds', () => {
    const pem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
    const exp = certNotAfterUnix(pem);
    expect(exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });
});
