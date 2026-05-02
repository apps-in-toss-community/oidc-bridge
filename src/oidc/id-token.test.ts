import { generateKeyPairSync } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { mintIdToken } from './id-token.js';
import { createSigningKeyRegistry } from './signing-keys.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('mintIdToken', () => {
  it('signs an RS256 JWT with mapped claims', async () => {
    const pem = genPem();
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem }],
    });
    const now = 1735686000;
    const jwt = await mintIdToken({
      issuer: 'https://oidc-bridge.aitc.dev',
      ttlSeconds: 3600,
      registry: reg,
      app: { clientId: 'app_abc' },
      tossClaims: {
        userKey: 42,
        scope: ['openid', 'profile', 'user_key'],
        agreedTerms: ['service'],
        tossAtExp: now + 1800,
      },
      now,
    });
    const { payload, protectedHeader } = await jwtVerify(jwt, createLocalJWKSet(reg.jwks()), {
      currentDate: new Date(now * 1000),
    });
    expect(protectedHeader.alg).toBe('RS256');
    expect(protectedHeader.kid).toBe('k1');
    expect(payload.iss).toBe('https://oidc-bridge.aitc.dev');
    expect(payload.aud).toBe('app_abc');
    expect(payload.sub).toBe('42');
    expect(payload.iat).toBe(now);
    expect(payload.exp).toBe(now + 3600);
    expect(payload.nbf).toBe(now);
    expect(payload.provider).toBe('toss');
    expect(payload.scope).toBe('openid profile user_key');
    expect(payload['toss:userKey']).toBe(42);
    expect(payload['toss:agreedTerms']).toEqual(['service']);
    expect(payload['toss:tossAccessTokenExpiresAt']).toBe(now + 1800);
  });
});
