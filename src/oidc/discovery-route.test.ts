import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createApp } from '../app.js';
import type { Storage } from '../storage/interface.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createInMemoryRevocationStore } from './revocation-store.js';
import { createSigningKeyRegistry } from './signing-keys.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

describe('discovery + jwks integration', () => {
  it('serves both endpoints with consistent jwks_uri', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const app = createApp({
      oidc: {
        config: {
          issuer: 'https://oidc-bridge.aitc.dev',
          activeKid: 'k1',
          signingKeys: [],
          idTokenTtlSeconds: 3600,
          defaultScope: 'openid profile user_key',
        },
        signingKeyRegistry: reg,
        storage: {
          getAppByClientId: async () => null,
          appendAudit: async () => {},
        } as unknown as Storage,
        tossAdapter: new MockTossAdapter(),
        resolveAppSealingKey: async () => Buffer.alloc(32, 11),
        revocationStore: createInMemoryRevocationStore(),
      },
    });
    const disc = await app.request('/.well-known/openid-configuration');
    expect(disc.status).toBe(200);
    const discJson = (await disc.json()) as { jwks_uri: string };
    expect(discJson.jwks_uri).toBe('https://oidc-bridge.aitc.dev/.well-known/jwks.json');
    const jwks = await app.request('/.well-known/jwks.json');
    expect(jwks.status).toBe(200);
    const jwksJson = (await jwks.json()) as { keys: { kid: string }[] };
    expect(jwksJson.keys[0]!.kid).toBe('k1');
  });
});
