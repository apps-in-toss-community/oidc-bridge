import { generateKeyPairSync } from 'node:crypto';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { createApp } from '../app.js';
import type { Storage } from '../storage/interface.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createInMemoryRevocationStore, type RevocationStore } from './revocation-store.js';
import { wrapSealedToken } from './sealed-token.js';
import { createSigningKeyRegistry } from './signing-keys.js';
import { userinfoRoute } from './userinfo-route.js';

function genPem(): string {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

interface FakeAppRow {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
  allowedOrigins: string[];
  ownershipStatus: 'verified' | 'pending' | 'lapsed';
  rawTokensEnabled: boolean;
}

function fakeStorage(app: FakeAppRow): Storage {
  return {
    async getApp(id: string) {
      return id === app.id ? (app as unknown as never) : null;
    },
    appendAudit: async () => {},
  } as unknown as Storage;
}

const sealingKey = Buffer.alloc(32, 13);

function makeAt(app: FakeAppRow, userKey = '42', tossAt = 'TOSS_AT_OPAQUE_FIXTURE'): string {
  return wrapSealedToken({
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id,
      tossUserKey: userKey,
      tossAt,
      tossRt: 'TOSS_RT_OPAQUE_FIXTURE',
      tossAtExp: 1735689600,
      issuedAt: 1735686000,
    },
  });
}

function buildHarness(app: FakeAppRow, opts: { revocationStore?: RevocationStore } = {}) {
  const h = new Hono();
  h.route(
    '/',
    userinfoRoute({
      storage: fakeStorage(app),
      tossAdapter: new MockTossAdapter(),
      resolveAppSealingKey: async () => sealingKey,
      revocationStore: opts.revocationStore ?? createInMemoryRevocationStore(),
    }),
  );
  return h;
}

const baseApp: FakeAppRow = {
  id: 'app_abc',
  clientId: 'app_abc',
  sealingKeyVersion: 1,
  allowedOrigins: ['https://app.example.com'],
  ownershipStatus: 'verified',
  rawTokensEnabled: false,
};

describe('GET /oidc/userinfo', () => {
  it('returns mapped claims for a valid AT', async () => {
    const h = buildHarness(baseApp);
    const at = makeAt(baseApp);
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.sub).toBe('42');
    expect(body.provider).toBe('toss');
    expect(body.scope).toBe('openid profile user_key');
    expect(body['toss:userKey']).toBe(42);
    expect(body['toss:agreedTerms']).toEqual(['service', 'marketing']);
    expect(typeof body['toss:tossAccessTokenExpiresAt']).toBe('number');
  });
});

describe('GET /oidc/userinfo error cases', () => {
  it('401 invalid_token when Authorization missing', async () => {
    const h = buildHarness(baseApp);
    const res = await h.request('/oidc/userinfo');
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toMatch(/Bearer/);
    expect(((await res.json()) as { error: string }).error).toBe('invalid_token');
  });

  it('401 invalid_token when scheme is not Bearer', async () => {
    const h = buildHarness(baseApp);
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: 'Basic abcdef' },
    });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token for malformed token', async () => {
    const h = buildHarness(baseApp);
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: 'Bearer not-a-token' },
    });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token when app unknown', async () => {
    const otherApp: FakeAppRow = { ...baseApp, id: 'app_other' };
    const at = makeAt(otherApp);
    const h = buildHarness(baseApp); // storage only knows baseApp
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token for tampered token', async () => {
    const h = buildHarness(baseApp);
    const at = makeAt(baseApp);
    const tampered = `${at.slice(0, -4)}AAAA`;
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tampered}` },
    });
    expect(res.status).toBe(401);
  });

  it('401 invalid_token when token is revoked', async () => {
    const store = createInMemoryRevocationStore();
    const at = makeAt(baseApp);
    store.revoke({ appId: baseApp.id, token: at });
    const h = buildHarness(baseApp, { revocationStore: store });
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error_description: string }).error_description).toMatch(
      /revoked/,
    );
  });

  it('502 upstream_error when Toss login-me fails', async () => {
    const h = buildHarness(baseApp);
    const at = makeAt(baseApp, '42', 'fail-at');
    const res = await h.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(502);
    expect(((await res.json()) as { error: string }).error).toBe('upstream_error');
  });
});

describe('createApp wiring (userinfo)', () => {
  it('mounts /oidc/userinfo via createApp', async () => {
    const reg = await createSigningKeyRegistry({
      activeKid: 'k1',
      signingKeys: [{ kid: 'k1', pem: genPem() }],
    });
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
        storage: fakeStorage(baseApp),
        tossAdapter: new MockTossAdapter(),
        resolveAppSealingKey: async () => sealingKey,
        revocationStore: createInMemoryRevocationStore(),
        now: () => 1735686000,
      },
    });
    const at = makeAt(baseApp);
    const res = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(200);
  });
});
