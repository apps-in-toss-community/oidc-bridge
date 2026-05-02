import { generateKeyPairSync } from 'node:crypto';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createSigningKeyRegistry } from './signing-keys.js';
import { tokenRoute } from './token-route.js';
import { createTokenService } from './token-service.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

interface FakeAppRow {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
  allowedOrigins: string[];
  ownershipStatus: 'verified' | 'lapsed' | 'pending';
}

function fakeStorage(app: FakeAppRow) {
  return {
    async getAppByClientId(clientId: string) {
      return clientId === app.clientId ? app : null;
    },
    appendAudit: async () => {},
  } as unknown as Storage;
}

async function buildHarness(opts: { app: FakeAppRow }) {
  const reg = await createSigningKeyRegistry({
    activeKid: 'k1',
    signingKeys: [{ kid: 'k1', pem: genPem() }],
  });
  const sealingKey = Buffer.alloc(32, 11);
  const tokenService = createTokenService({
    adapter: new MockTossAdapter(),
    registry: reg,
    issuer: 'https://oidc-bridge.aitc.dev',
    idTokenTtlSeconds: 3600,
    resolveAppSealingKey: async () => sealingKey,
    now: () => 1735686000,
  });
  const honoApp = new Hono();
  honoApp.route(
    '/',
    tokenRoute({
      storage: fakeStorage(opts.app),
      tokenService,
      resolveAppSealingKey: async () => sealingKey,
    }),
  );
  return honoApp;
}

describe('POST /oidc/token (public client)', () => {
  const app: FakeAppRow = {
    id: 'app_abc',
    clientId: 'app_abc',
    sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'],
    ownershipStatus: 'verified',
  };

  it('happy authorization_code via JSON body', async () => {
    const h = await buildHarness({ app });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://app.example.com',
      },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: 'good',
        client_id: 'app_abc',
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      token_type: string;
      access_token: string;
      refresh_token: string;
      id_token: string;
    };
    expect(body.token_type).toBe('Bearer');
    expect(body.access_token).toMatch(/^ait_/);
    expect(body.refresh_token).toMatch(/^ait_/);
    expect(body.id_token.split('.')).toHaveLength(3);
  });

  it('happy authorization_code via form-encoded body', async () => {
    const h = await buildHarness({ app });
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        origin: 'https://app.example.com',
      },
      body: 'grant_type=authorization_code&code=good&client_id=app_abc',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    expect(body.access_token).toMatch(/^ait_/);
  });
});

describe('POST /oidc/token (refresh_token)', () => {
  const app: FakeAppRow = {
    id: 'app_abc',
    clientId: 'app_abc',
    sealingKeyVersion: 1,
    allowedOrigins: ['https://app.example.com'],
    ownershipStatus: 'verified',
  };

  it('happy refresh after authorization_code', async () => {
    const h = await buildHarness({ app });
    const firstRes = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: 'good',
        client_id: 'app_abc',
      }),
    });
    const first = (await firstRes.json()) as { refresh_token: string; access_token: string };
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: first.refresh_token,
        client_id: 'app_abc',
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string };
    expect(body.access_token).toMatch(/^ait_/);
    expect(body.access_token).not.toBe(first.access_token);
  });

  it('refresh with tampered token returns 401 invalid_grant', async () => {
    const h = await buildHarness({ app });
    const firstRes = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: 'good',
        client_id: 'app_abc',
      }),
    });
    const first = (await firstRes.json()) as { refresh_token: string };
    const tampered = `${first.refresh_token.slice(0, -4)}AAAA`;
    const res = await h.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://app.example.com' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: tampered,
        client_id: 'app_abc',
      }),
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string };
    expect(body.error).toBe('invalid_grant');
  });
});
