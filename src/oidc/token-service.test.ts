import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { unwrapSealedToken } from './sealed-token.js';
import { createSigningKeyRegistry } from './signing-keys.js';
import { createTokenService } from './token-service.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('tokenService.authorizationCode', () => {
  it('returns ait_AT/RT, id_token, expires_in, scope and seals Toss tokens', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 11);
    const service = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://oidc-bridge.aitc.dev',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => sealingKey,
      now: () => 1735686000,
    });
    const out = await service.authorizationCode({
      app: { id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1 },
      authorizationCode: 'good',
    });
    expect(out.token_type).toBe('Bearer');
    expect(out.expires_in).toBe(3600);
    expect(out.scope).toBe('openid profile user_key');
    expect(out.access_token).toMatch(/^ait_/);
    expect(out.refresh_token).toMatch(/^ait_/);
    expect(out.id_token.split('.')).toHaveLength(3);
    const at = unwrapSealedToken({
      token: out.access_token,
      resolveKey: () => sealingKey,
      expectedAppId: 'app_abc',
      expectedTossUserKey: '42',
    });
    expect(at.tossAt).toBe('TOSS_AT_OPAQUE_FIXTURE');
    expect(at.tossRt).toBe('TOSS_RT_OPAQUE_FIXTURE');
  });

  it('propagates Toss invalid_grant', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const service = createTokenService({
      adapter: new MockTossAdapter(),
      registry: reg,
      issuer: 'https://x',
      idTokenTtlSeconds: 3600,
      resolveAppSealingKey: async () => Buffer.alloc(32, 1),
      now: () => 1,
    });
    await expect(
      service.authorizationCode({
        app: { id: 'a', clientId: 'a', sealingKeyVersion: 1 },
        authorizationCode: 'fail-code',
      }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });
});
