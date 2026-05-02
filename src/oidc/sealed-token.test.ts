import { describe, expect, it } from 'vitest';
import { wrapSealedToken } from './sealed-token.js';

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
