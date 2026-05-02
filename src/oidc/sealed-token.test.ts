import { describe, expect, it } from 'vitest';
import {
  peekSealedTokenAppId,
  peekSealedTokenUserKey,
  peekSealedTokenVersion,
  unwrapSealedToken,
  wrapSealedToken,
} from './sealed-token.js';

const PAYLOAD = {
  appId: 'app_abc',
  tossUserKey: 'u_42',
  tossAt: 'TOSS_AT_OPAQUE',
  tossRt: 'TOSS_RT_OPAQUE',
  tossAtExp: 1735689600,
  issuedAt: 1735686000,
};

// Wire format: version(1) || appIdLen(1) || appId(n) || userKeyLen(1) || userKey(m) || iv(12) || ciphertext || tag(16)
// PAYLOAD has appId='app_abc' (7 bytes) and tossUserKey='u_42' (4 bytes), so:
//  - byte 0:        version
//  - byte 1:        appIdLen = 7
//  - bytes 2..8:    appId
//  - byte 9:        userKeyLen = 4
//  - bytes 10..13:  userKey
//  - bytes 14..25:  iv (12 bytes)
//  - bytes 26..-17: ciphertext
//  - bytes -16..:   tag
const APPID_HINT_OFFSET = 2;
const USERKEY_HINT_OFFSET = 10;

describe('wrapSealedToken', () => {
  const sealingKey = Buffer.alloc(32, 7);

  it('produces ait_-prefixed base64url with version byte 1', () => {
    const token = wrapSealedToken({
      sealingKey,
      sealingKeyVersion: 1,
      payload: PAYLOAD,
    });
    expect(token).toMatch(/^ait_[A-Za-z0-9_-]+$/);
    const body = token.slice(4);
    const buf = Buffer.from(body, 'base64url');
    expect(buf[0]).toBe(1);
    expect(buf.length).toBeGreaterThan(30);
  });

  it('different calls produce different IVs and ciphertexts', () => {
    const t1 = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    const t2 = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    expect(t1).not.toBe(t2);
  });
});

describe('unwrapSealedToken', () => {
  const sealingKey = Buffer.alloc(32, 7);

  it('roundtrips a wrapped token', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    const got = unwrapSealedToken({
      token: tok,
      resolveKey: (version) => {
        expect(version).toBe(1);
        return sealingKey;
      },
      expectedAppId: PAYLOAD.appId,
    });
    expect(got).toEqual(PAYLOAD);
  });

  it('rejects tampered ciphertext', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    const body = Buffer.from(tok.slice(4), 'base64url');
    // Flip a byte just before the tag — safely inside ciphertext.
    const idx = body.length - 16 - 1;
    body[idx] = (body[idx]! ^ 0x01) & 0xff;
    const tampered = `ait_${body.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: tampered,
        resolveKey: () => sealingKey,
        expectedAppId: PAYLOAD.appId,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('rejects swap to different app via expectedAppId AAD mismatch', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    expect(() =>
      unwrapSealedToken({
        token: tok,
        resolveKey: () => sealingKey,
        expectedAppId: 'app_other',
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('rejects token without ait_ prefix', () => {
    expect(() =>
      unwrapSealedToken({
        token: 'notait_abc',
        resolveKey: () => sealingKey,
        expectedAppId: PAYLOAD.appId,
      }),
    ).toThrow(/SEALED_TOKEN_BAD_FORMAT/);
  });

  it('rejects cross-version replay (v1 wrapper read with v2 key resolver)', () => {
    const v1Key = Buffer.alloc(32, 7);
    const v2Key = Buffer.alloc(32, 9);
    const tok = wrapSealedToken({ sealingKey: v1Key, sealingKeyVersion: 1, payload: PAYLOAD });
    const body = Buffer.from(tok.slice(4), 'base64url');
    body[0] = 2;
    const forged = `ait_${body.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: forged,
        resolveKey: (v) => (v === 2 ? v2Key : v1Key),
        expectedAppId: PAYLOAD.appId,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });

  it('peeks userKey hint without decrypting', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    expect(peekSealedTokenUserKey(tok)).toBe('u_42');
  });

  it('rejects tampered userKey hint', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    const buf = Buffer.from(tok.slice(4), 'base64url');
    buf[USERKEY_HINT_OFFSET] = (buf[USERKEY_HINT_OFFSET]! ^ 0x01) & 0xff;
    const forged = `ait_${buf.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: forged,
        resolveKey: () => sealingKey,
        expectedAppId: PAYLOAD.appId,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });
});

describe('peekSealedTokenAppId', () => {
  const sealingKey = Buffer.alloc(32, 7);

  it('reads appId from preamble without decrypting', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    expect(peekSealedTokenAppId(tok)).toBe(PAYLOAD.appId);
  });

  it('throws on bad format', () => {
    expect(() => peekSealedTokenAppId('xxx')).toThrow(/SEALED_TOKEN_BAD_FORMAT/);
  });

  it('rejects tampered appId hint (preamble byte vs expectedAppId mismatch)', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    const buf = Buffer.from(tok.slice(4), 'base64url');
    buf[APPID_HINT_OFFSET] = (buf[APPID_HINT_OFFSET]! ^ 0x01) & 0xff;
    const forged = `ait_${buf.toString('base64url')}`;
    expect(() =>
      unwrapSealedToken({
        token: forged,
        resolveKey: () => sealingKey,
        expectedAppId: PAYLOAD.appId,
      }),
    ).toThrow(/SEALED_TOKEN_TAMPERED/);
  });
});

describe('peekSealedTokenVersion', () => {
  const sealingKey = Buffer.alloc(32, 7);

  it('returns the version byte without decrypting', () => {
    const tok = wrapSealedToken({ sealingKey, sealingKeyVersion: 1, payload: PAYLOAD });
    expect(peekSealedTokenVersion(tok)).toBe(1);
  });

  it('throws on bad format', () => {
    expect(() => peekSealedTokenVersion('xxx')).toThrow(/SEALED_TOKEN_BAD_FORMAT/);
  });
});
