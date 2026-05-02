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

interface FakeAppRow {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
  allowedOrigins: string[];
  ownershipStatus: 'verified';
  rawTokensEnabled: boolean;
  clientSecretHashes: string[];
}

function fakeStorage(app: FakeAppRow): Storage {
  return {
    async getApp(id: string) {
      return id === app.id ? (app as unknown as never) : null;
    },
    async getAppByClientId(clientId: string) {
      return clientId === app.clientId ? (app as unknown as never) : null;
    },
    appendAudit: async () => {},
  } as unknown as Storage;
}

describe('zero-code flow end-to-end (mock Toss)', () => {
  it('token → userinfo → revoke pipeline succeeds', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
    const sealingKey = Buffer.alloc(32, 22);
    const adapter = new MockTossAdapter();
    const fakeApp: FakeAppRow = {
      id: 'app_abc',
      clientId: 'app_abc',
      sealingKeyVersion: 1,
      allowedOrigins: ['https://app.example.com'],
      ownershipStatus: 'verified',
      rawTokensEnabled: false,
      clientSecretHashes: [],
    };
    const app = createApp({
      oidc: {
        config: {
          issuer: 'https://oidc-bridge.aitc.dev',
          activeKid: 'k1',
          signingKeys: [{ kid: 'k1', pem: 'unused-here' }],
          idTokenTtlSeconds: 3600,
          defaultScope: 'openid profile user_key',
        },
        signingKeyRegistry: reg,
        storage: fakeStorage(fakeApp),
        tossAdapter: adapter,
        resolveAppSealingKey: async () => sealingKey,
        revocationStore: createInMemoryRevocationStore(),
        now: () => 1735686000,
      },
    });

    const tokenRes = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: 'good',
        client_id: 'app_abc',
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      refresh_token: string;
      id_token: string;
    };
    expect(tokens.access_token).toMatch(/^ait_/);
    expect(tokens.refresh_token).toMatch(/^ait_/);

    const infoRes = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(infoRes.status).toBe(200);
    const info = (await infoRes.json()) as Record<string, unknown>;
    expect(info.sub).toBe('42');
    expect(info.provider).toBe('toss');

    const revokeRtRes = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(tokens.refresh_token)}&token_type_hint=refresh_token`,
    });
    expect(revokeRtRes.status).toBe(200);
    expect(adapter.accessRemoveCalls).toEqual([{ appId: 'app_abc', userKey: '42' }]);

    const infoAgain = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(infoAgain.status).toBe(200);

    const revokeAtRes = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(tokens.access_token)}&token_type_hint=access_token`,
    });
    expect(revokeAtRes.status).toBe(200);

    const infoAfterAtRevoke = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(infoAfterAtRevoke.status).toBe(401);
  });
});
