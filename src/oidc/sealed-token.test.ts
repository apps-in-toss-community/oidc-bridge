import { describe, expect, it } from 'vitest';
import { unwrapSealedToken, wrapSealedToken } from './sealed-token.js';

describe('wrapSealedToken', () => {
  const sealingKey = Buffer.alloc(32, 7);
  const payload = {
    appId: 'app_abc',
    tossUserKey: 'u_42',
    tossAt: 'TOSS_AT_OPAQUE',
    tossRt: 'TOSS_RT_OPAQUE',
    tossAtExp: 1735689600,
    issuedAt: 1735686000,
  };

  it('produces ait_-prefixed base64url with version byte 1', () => {
    const token = wrapSealedToken({
      sealingKey,
      sealingKeyVersion: 1,
      payload,
    });
    expect(token).toMatch(/^ait_[A-Za-z0-9_-]+$/);
    const body = token.slice(4);
    const buf = Buffer.from(body, 'base64url');
    expect(buf[0]).toBe(1);
    expect(buf.length).toBeGreaterThan(30);
  });

  it('different calls produce different IVs and ciphertexts', () => {
    const t1 = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    const t2 = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    expect(t1).not.toBe(t2);
  });
});

describe('unwrapSealedToken', () => {
  const sealingKey = Buffer.alloc(32, 7);
  const payload = {
    appId: 'app_abc',
    tossUserKey: 'u_42',
    tossAt: 'TOSS_AT_OPAQUE',
    tossRt: 'TOSS_RT_OPAQUE',
    tossAtExp: 1735689600,
    issuedAt: 1735686000,
  };

  it('roundtrips a wrapped token', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    const got = unwrapSealedToken({
      token: tok,
      resolveKey: (version) => {
        expect(version).toBe(1);
        return sealingKey;
      },
      expectedAppId: payload.appId,
      expectedTossUserKey: payload.tossUserKey,
    });
    expect(got).toEqual(payload);
  });

  it('rejects tampered ciphertext', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    const body = Buffer.from(tok.slice(4), 'base64url');
    body[20] = (body[20]! ^ 0x01) & 0xff;
    const tampered = `ait_${body.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: tampered,
        resolveKey: () => sealingKey,
        expectedAppId: payload.appId,
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('rejects swap to different app via expectedAppId AAD mismatch', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload });
    expect(() =>
      unwrapSealedToken({
        token: tok,
        resolveKey: () => sealingKey,
        expectedAppId: 'app_other',
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('rejects token without ait_ prefix', () => {
    expect(() =>
      unwrapSealedToken({
        token: 'notait_abc',
        resolveKey: () => sealingKey,
        expectedAppId: payload.appId,
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_BAD_FORMAT/);
  });

  it('rejects cross-version replay (v1 wrapper read with v2 key resolver)', () => {
    const v1Key = Buffer.alloc(32, 7);
    const v2Key = Buffer.alloc(32, 9);
    const tok = wrapSealedToken({ sealingKey: v1Key, sealingKeyVersion: 1, payload });
    const body = Buffer.from(tok.slice(4), 'base64url');
    body[0] = 2;
    const forged = `ait_${body.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: forged,
        resolveKey: (v) => (v === 2 ? v2Key : v1Key),
        expectedAppId: payload.appId,
        expectedTossUserKey: payload.tossUserKey,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });
});
