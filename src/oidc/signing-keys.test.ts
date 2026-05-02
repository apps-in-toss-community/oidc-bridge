import { generateKeyPairSync } from 'node:crypto';
import { createLocalJWKSet, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { createSigningKeyRegistry } from './signing-keys.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('createSigningKeyRegistry', () => {
  it('exposes the active signer and a JWKS containing every loaded kid', async () => {
    const pemA = genPem();
    const pemB = genPem();
    const reg = await createSigningKeyRegistry({
      activeKid: 'a',
      signingKeys: [
        { kid: 'a', pem: pemA },
        { kid: 'b', pem: pemB },
      ],
    });
    const jwks = reg.jwks();
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual(['a', 'b']);
    for (const k of jwks.keys) {
      expect(k.alg).toBe('RS256');
      expect(k.use).toBe('sig');
      expect(k.kty).toBe('RSA');
    }
    const signed = await new SignJWT({ hello: 'world' })
      .setProtectedHeader({ alg: 'RS256', kid: reg.activeKid })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(reg.activeSigner);
    const set = createLocalJWKSet(jwks);
    const { payload } = await jwtVerify(signed, set);
    expect(payload.hello).toBe('world');
  });

  it('throws when activeKid not in signingKeys', async () => {
    const pem = genPem();
    await expect(
      createSigningKeyRegistry({ activeKid: 'missing', signingKeys: [{ kid: 'a', pem }] }),
    ).rejects.toThrow(/activeKid/);
  });
});
