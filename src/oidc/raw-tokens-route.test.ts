import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { rawTokensRoute } from './raw-tokens-route.js';
import { createInMemoryRevocationStore, type RevocationStore } from './revocation-store.js';
import { wrapSealedToken } from './sealed-token.js';

interface FakeAppRow {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
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

function makeAt(app: FakeAppRow): string {
  return wrapSealedToken({
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id,
      tossUserKey: '42',
      tossAt: 'TOSS_AT_OPAQUE_FIXTURE',
      tossRt: 'TOSS_RT_OPAQUE_FIXTURE',
      tossAtExp: 1735690000,
      issuedAt: 1735686000,
    },
  });
}

function buildHarness(app: FakeAppRow, opts: { store?: RevocationStore; now?: () => number } = {}) {
  const h = new Hono();
  h.route(
    '/',
    rawTokensRoute({
      storage: fakeStorage(app),
      resolveAppSealingKey: async () => sealingKey,
      revocationStore: opts.store ?? createInMemoryRevocationStore(),
      now: opts.now ?? (() => 1735686100),
    }),
  );
  return h;
}

const disabledApp: FakeAppRow = {
  id: 'app_abc',
  clientId: 'app_abc',
  sealingKeyVersion: 1,
  rawTokensEnabled: false,
};
const enabledApp: FakeAppRow = { ...disabledApp, rawTokensEnabled: true };

describe('GET /oidc/raw-tokens', () => {
  it('returns 404 when rawTokensEnabled is false', async () => {
    const h = buildHarness(disabledApp);
    const at = makeAt(disabledApp);
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(404);
  });

  it('returns access_token and expires_in when enabled', async () => {
    const h = buildHarness(enabledApp);
    const at = makeAt(enabledApp);
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { access_token: string; expires_in: number };
    expect(body.access_token).toBe('TOSS_AT_OPAQUE_FIXTURE');
    expect(body.expires_in).toBe(1735690000 - 1735686100);
  });

  it('never returns refresh_token (no field, no leaked value)', async () => {
    const h = buildHarness(enabledApp);
    const at = makeAt(enabledApp);
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: `Bearer ${at}` },
    });
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).not.toHaveProperty('refresh_token');
    expect(JSON.stringify(body)).not.toContain('TOSS_RT_OPAQUE_FIXTURE');
  });

  it('returns 401 when no bearer', async () => {
    const h = buildHarness(enabledApp);
    const res = await h.request('/oidc/raw-tokens');
    expect(res.status).toBe(401);
  });

  it('returns 401 when token revoked', async () => {
    const at = makeAt(enabledApp);
    const store = createInMemoryRevocationStore();
    store.revoke({ appId: enabledApp.id, token: at });
    const h = buildHarness(enabledApp, { store });
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(401);
  });

  it('returns expires_in clamped to 0 when AT already expired', async () => {
    const h = buildHarness(enabledApp, { now: () => 9999999999 });
    const at = makeAt(enabledApp);
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { expires_in: number };
    expect(body.expires_in).toBe(0);
  });

  it('returns 401 when token is malformed', async () => {
    const h = buildHarness(enabledApp);
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: 'Bearer not-a-token' },
    });
    expect(res.status).toBe(401);
  });

  it('returns 401 when app unknown', async () => {
    const otherApp: FakeAppRow = { ...enabledApp, id: 'app_other' };
    const at = makeAt(otherApp);
    const h = buildHarness(enabledApp);
    const res = await h.request('/oidc/raw-tokens', {
      headers: { authorization: `Bearer ${at}` },
    });
    expect(res.status).toBe(401);
  });
});
