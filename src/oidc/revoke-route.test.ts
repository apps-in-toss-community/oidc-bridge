import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { MockTossAdapter } from '../toss/mock-adapter.js';
import { createInMemoryRevocationStore, type RevocationStore } from './revocation-store.js';
import { revokeRoute } from './revoke-route.js';
import { wrapSealedToken } from './sealed-token.js';

interface FakeAppRow {
  id: string;
  clientId: string;
  sealingKeyVersion: number;
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

function makeToken(app: FakeAppRow, userKey = '42'): string {
  return wrapSealedToken({
    sealingKey,
    sealingKeyVersion: app.sealingKeyVersion,
    payload: {
      appId: app.id,
      tossUserKey: userKey,
      tossAt: 'TOSS_AT_OPAQUE_FIXTURE',
      tossRt: 'TOSS_RT_OPAQUE_FIXTURE',
      tossAtExp: 1735689600,
      issuedAt: 1735686000,
    },
  });
}

function buildHarness(
  app: FakeAppRow,
  opts: { adapter?: MockTossAdapter; store?: RevocationStore } = {},
) {
  const adapter = opts.adapter ?? new MockTossAdapter();
  const store = opts.store ?? createInMemoryRevocationStore();
  const h = new Hono();
  h.route(
    '/',
    revokeRoute({
      storage: fakeStorage(app),
      tossAdapter: adapter,
      resolveAppSealingKey: async () => sealingKey,
      revocationStore: store,
    }),
  );
  return { app: h, adapter, store };
}

const baseApp: FakeAppRow = { id: 'app_abc', clientId: 'app_abc', sealingKeyVersion: 1 };

describe('POST /oidc/revoke', () => {
  it('returns 200 for unknown token (not ait_)', async () => {
    const { app: h } = buildHarness(baseApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'token=not-ait',
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 with no body params (treats as unknown token)', async () => {
    const { app: h } = buildHarness(baseApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: '',
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 when content-type is unsupported', async () => {
    const { app: h } = buildHarness(baseApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'whatever',
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 when token is malformed but ait_ prefixed', async () => {
    const { app: h } = buildHarness(baseApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'token=ait_AAAAA',
    });
    expect(res.status).toBe(200);
  });

  it('marks an access_token revoked locally and does NOT call accessRemove', async () => {
    const { app: h, adapter, store } = buildHarness(baseApp);
    const at = makeToken(baseApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(at)}&token_type_hint=access_token`,
    });
    expect(res.status).toBe(200);
    expect(store.isRevoked({ appId: baseApp.id, token: at })).toBe(true);
    expect(adapter.accessRemoveCalls).toEqual([]);
  });

  it('refresh_token hint triggers accessRemove on Toss', async () => {
    const { app: h, adapter, store } = buildHarness(baseApp);
    const rt = makeToken(baseApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(rt)}&token_type_hint=refresh_token`,
    });
    expect(res.status).toBe(200);
    expect(adapter.accessRemoveCalls).toEqual([{ appId: baseApp.id, userKey: '42' }]);
    expect(store.isRevoked({ appId: baseApp.id, token: rt })).toBe(true);
  });

  it('still returns 200 even if accessRemove on Toss fails', async () => {
    const { app: h, store } = buildHarness(baseApp);
    const rt = wrapSealedToken({
      sealingKey,
      sealingKeyVersion: baseApp.sealingKeyVersion,
      payload: {
        appId: baseApp.id,
        tossUserKey: 'fail-userkey',
        tossAt: 'x',
        tossRt: 'x',
        tossAtExp: 1,
        issuedAt: 1,
      },
    });
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(rt)}&token_type_hint=refresh_token`,
    });
    expect(res.status).toBe(200);
    expect(store.isRevoked({ appId: baseApp.id, token: rt })).toBe(true);
  });

  it('returns 200 when app is unknown (token sealed for another app)', async () => {
    const otherApp: FakeAppRow = { ...baseApp, id: 'app_other' };
    const { app: h, store } = buildHarness(baseApp);
    const at = makeToken(otherApp);
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(at)}&token_type_hint=access_token`,
    });
    expect(res.status).toBe(200);
    expect(store.isRevoked({ appId: otherApp.id, token: at })).toBe(false);
  });

  it('returns 200 for tampered ait_ token (does not throw)', async () => {
    const { app: h, store } = buildHarness(baseApp);
    const at = makeToken(baseApp);
    const tampered = `${at.slice(0, -4)}AAAA`;
    const res = await h.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(tampered)}&token_type_hint=access_token`,
    });
    expect(res.status).toBe(200);
    expect(store.isRevoked({ appId: baseApp.id, token: tampered })).toBe(false);
  });
});
