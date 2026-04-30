import { describe, expect, it } from 'vitest';
import { deriveSealingKey, sealAccessToken, unsealAccessToken } from './sealed-token.js';

const masterKey = Buffer.alloc(32, 0xab);
const tenantId = 'tnt_abcdefghjkmnpqrstvwxyz01';

describe('deriveSealingKey', () => {
  it('returns a 32-byte buffer', () => {
    const key = deriveSealingKey(masterKey, tenantId, 1);
    expect(key).toHaveLength(32);
  });

  it('is deterministic for same inputs', () => {
    const a = deriveSealingKey(masterKey, tenantId, 1);
    const b = deriveSealingKey(masterKey, tenantId, 1);
    expect(a.equals(b)).toBe(true);
  });

  it('differs across tenants', () => {
    const a = deriveSealingKey(masterKey, 'tnt_aaaaaaaaaaaaaaaaaaaaaaaa', 1);
    const b = deriveSealingKey(masterKey, 'tnt_bbbbbbbbbbbbbbbbbbbbbbbb', 1);
    expect(a.equals(b)).toBe(false);
  });

  it('differs across versions', () => {
    const a = deriveSealingKey(masterKey, tenantId, 1);
    const b = deriveSealingKey(masterKey, tenantId, 2);
    expect(a.equals(b)).toBe(false);
  });
});

describe('seal/unseal access token', () => {
  const payload = {
    tenant_id: tenantId,
    toss_access_token: 'toss-AT-fake-jwt',
    toss_refresh_token: 'toss-RT-fake',
    exp: 1_900_000_000,
  };

  it('round-trips through wrap/unwrap', () => {
    const token = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    expect(token).toMatch(/^aitc_[A-Za-z0-9_-]+$/);
    const unsealed = unsealAccessToken({ token, masterKey, sealingKeyVersionOf: () => 1 });
    expect(unsealed).toEqual(payload);
  });

  it('rejects tampered ciphertext', () => {
    const token = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    const tampered = `${token.slice(0, -4)}AAAA`;
    expect(() =>
      unsealAccessToken({ token: tampered, masterKey, sealingKeyVersionOf: () => 1 }),
    ).toThrow(/tamper|auth/i);
  });

  it('rejects wrong prefix', () => {
    expect(() =>
      unsealAccessToken({ token: 'bearer_xxx', masterKey, sealingKeyVersionOf: () => 1 }),
    ).toThrow(/format/i);
  });

  it('rejects when sealing_key_version mismatches', () => {
    const token = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    expect(() => unsealAccessToken({ token, masterKey, sealingKeyVersionOf: () => 2 })).toThrow(
      /auth|tamper/i,
    );
  });

  it('produces non-deterministic output (random nonce)', () => {
    const a = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    const b = sealAccessToken({ payload, masterKey, sealingKeyVersion: 1 });
    expect(a).not.toBe(b);
  });
});
