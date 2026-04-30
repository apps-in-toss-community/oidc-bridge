import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.js';
import type { Config } from '../config.js';
import { createFsStore } from '../tenants/fs-store.js';
import type { TenantStore } from '../tenants/store.js';
import { sealAccessToken } from './sealed-token.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');
const signingKeyPem = readFileSync('src/__fixtures__/test-signing.key.pem', 'utf8');

function buildConfig(dataDir: string): Config {
  return {
    issuer: 'https://oidc-bridge.test',
    signingKeyPem,
    masterKey: Buffer.alloc(32, 0xab),
    adminToken: 'admin',
    tenantStore: { kind: 'fs', dataDir },
    tossApiBase: 'https://apps-in-toss-api.test',
  };
}

async function setupTenant(): Promise<{
  app: Hono;
  config: Config;
  store: TenantStore;
  tenantId: string;
  sealedAt: string;
}> {
  const dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
  const config = buildConfig(dataDir);
  const store = await createFsStore(dataDir);
  const { tenant } = await store.create({
    name: 't',
    environment: 'sandbox',
    cert_pem: certPem,
    key_pem: keyPem,
  });
  const app = await createApp({ config, store });
  const sealedAt = sealAccessToken({
    payload: {
      tenant_id: tenant.id,
      toss_access_token: 'real-toss-at',
      toss_refresh_token: 'real-toss-rt',
      exp: Math.floor(Date.now() / 1000) + 3600,
    },
    masterKey: config.masterKey,
    sealingKeyVersion: tenant.sealing_key_version,
  });
  return { app, config, store, tenantId: tenant.id, sealedAt };
}

describe('POST /oidc/revoke (RFC 7009)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns 200 on happy path and calls upstream remove-by-access-token', async () => {
    const { app, sealedAt } = await setupTenant();
    const fetchStub = vi.fn(
      async () =>
        new Response(JSON.stringify({ resultType: 'SUCCESS', success: {} }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    vi.stubGlobal('fetch', fetchStub);
    const res = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: sealedAt }),
    });
    expect(res.status).toBe(200);
    expect(fetchStub).toHaveBeenCalled();
  });

  it('returns 200 even when token field missing', async () => {
    const { app } = await setupTenant();
    const res = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({}),
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 even when token is malformed', async () => {
    const { app } = await setupTenant();
    const res = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: 'not-a-sealed-token' }),
    });
    expect(res.status).toBe(200);
  });

  it('returns 200 even when upstream FAILs', async () => {
    const { app, sealedAt } = await setupTenant();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              resultType: 'FAIL',
              error: { reason: 'TOKEN_NOT_FOUND', description: 'gone' },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );
    const res = await app.request('/oidc/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: sealedAt }),
    });
    expect(res.status).toBe(200);
  });
});
