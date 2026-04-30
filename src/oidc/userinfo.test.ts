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

describe('GET /oidc/userinfo', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns claims from /login-me', async () => {
    const { app, sealedAt } = await setupTenant();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: {
                userKey: 4200000000001,
                scope: 'user_key',
                agreedTerms: ['T1'],
                name: 'enc-name',
              },
            }),
          ),
      ),
    );
    const res = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${sealedAt}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.sub).toBe('4200000000001');
    expect(body['toss:userKey']).toBe(4200000000001);
    expect(body['toss:agreedTerms']).toEqual(['T1']);
    expect(body.name).toBe('enc-name');
  });

  it('returns 401 invalid_token when Bearer missing', async () => {
    const { app } = await setupTenant();
    const res = await app.request('/oidc/userinfo');
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_token' });
  });

  it('returns 401 invalid_token when bearer is tampered', async () => {
    const { app, sealedAt } = await setupTenant();
    // Flip a character in the body of the sealed token to break AEAD.
    const tampered = `${sealedAt.slice(0, -3)}XXX`;
    const res = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${tampered}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_token' });
  });

  it('returns 401 invalid_token when /login-me FAILs', async () => {
    const { app, sealedAt } = await setupTenant();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              resultType: 'FAIL',
              error: { reason: 'INVALID_TOKEN' },
            }),
          ),
      ),
    );
    const res = await app.request('/oidc/userinfo', {
      headers: { authorization: `Bearer ${sealedAt}` },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_token' });
  });
});
