import { readFileSync } from 'node:fs';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { computeKid, exportJwks, signIdToken } from './id-token.js';

const signingKeyPem = readFileSync('src/__fixtures__/test-signing.key.pem', 'utf8');

describe('signIdToken + JWKS verify', () => {
  it('round-trips: sign with private, verify with JWKS public half', async () => {
    const claims = {
      sub: '4200000000001',
      iss: 'https://oidc-bridge.aitc.dev',
      aud: 'tnt_abcdefghjkmnpqrstvwxyz01',
      iat: 1_700_000_000,
      exp: 1_700_003_600,
      provider: 'toss' as const,
      scope: 'openid user_key',
      'toss:userKey': 4200000000001,
    };
    const jwt = await signIdToken({ claims, signingKeyPem });
    const jwks = await exportJwks(signingKeyPem);
    const set = createLocalJWKSet(jwks);
    const { payload, protectedHeader } = await jwtVerify(jwt, set, {
      issuer: claims.iss,
      audience: claims.aud,
      clockTolerance: Infinity, // static historical timestamps in fixture
    });
    expect(protectedHeader.alg).toBe('RS256');
    expect(protectedHeader.kid).toBe(jwks.keys[0]!.kid);
    expect(payload.sub).toBe(claims.sub);
    expect(payload['toss:userKey']).toBe(4200000000001);
  });

  it('exposes a deterministic kid (RFC 7638 thumbprint)', async () => {
    const a = await computeKid(signingKeyPem);
    const b = await computeKid(signingKeyPem);
    expect(a).toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/); // base64url SHA-256
  });

  it('JWKS publishes only the public half (no `d`, no `p`, no `q`)', async () => {
    const jwks = await exportJwks(signingKeyPem);
    expect(jwks.keys).toHaveLength(1);
    const k = jwks.keys[0] as unknown as Record<string, unknown>;
    expect(k.kty).toBe('RSA');
    expect(k.use).toBe('sig');
    expect(k.alg).toBe('RS256');
    expect(k.kid).toBeTypeOf('string');
    expect(k.n).toBeTypeOf('string');
    expect(k.e).toBeTypeOf('string');
    expect(k.d).toBeUndefined();
    expect(k.p).toBeUndefined();
    expect(k.q).toBeUndefined();
  });
});
