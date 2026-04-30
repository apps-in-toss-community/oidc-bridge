import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Hono } from 'hono';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../app.js';
import type { Config } from '../config.js';
import { createFsStore } from '../tenants/fs-store.js';
import type { TenantStore } from '../tenants/store.js';
import { exportJwks } from './id-token.js';
import { unsealAccessToken } from './sealed-token.js';

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
  clientSecret: string;
}> {
  const dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
  const config = buildConfig(dataDir);
  const store = await createFsStore(dataDir);
  const { tenant, client_secret } = await store.create({
    name: 't',
    environment: 'sandbox',
    cert_pem: certPem,
    key_pem: keyPem,
  });
  const app = await createApp({ config, store });
  return { app, config, store, tenantId: tenant.id, clientSecret: client_secret };
}

describe('POST /oidc/token — authorization_code', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('happy path: returns access_token + id_token + refresh_token', async () => {
    const { app, config, tenantId, clientSecret } = await setupTenant();
    const fakeAt = 'h.eyJleHAiOjE5MDAwMDAwMDB9.s'; // base64url payload {"exp":1900000000}
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.endsWith('/generate-token')) {
          return new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: {
                accessToken: fakeAt,
                refreshToken: 'rt-fake',
                tokenType: 'Bearer',
                expiresIn: 3600,
                scope: 'user_key',
              },
            }),
          );
        }
        if (url.endsWith('/login-me')) {
          return new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: { userKey: 4200000000001, scope: 'user_key', agreedTerms: ['T1'] },
            }),
          );
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );

    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'auth_xxx',
        scope: 'openid user_key',
      }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: expect.any(Number) });
    expect(body.access_token as string).toMatch(/^aitc_/);
    expect(body.refresh_token as string).toMatch(/^aitc_/);

    const jwks = await exportJwks(signingKeyPem);
    const { payload } = await jwtVerify(body.id_token as string, createLocalJWKSet(jwks), {
      issuer: config.issuer,
      audience: tenantId,
    });
    expect(payload.sub).toBe('4200000000001');
    expect(payload['toss:userKey']).toBe(4200000000001);

    const unsealed = unsealAccessToken({
      token: body.access_token as string,
      masterKey: config.masterKey,
      sealingKeyVersionOf: () => 1,
    });
    expect(unsealed.tenant_id).toBe(tenantId);
    expect(unsealed.toss_access_token).toBe(fakeAt);
  });

  it('returns invalid_client when basic auth is wrong', async () => {
    const { app, tenantId } = await setupTenant();
    const enc = Buffer.from(`${tenantId}:wrong`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('returns invalid_client when tenant does not exist', async () => {
    const { app } = await setupTenant();
    const enc = Buffer.from('tnt_doesnotexistxxxxxxxxxxxxx:secret').toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('returns invalid_client when no client auth supplied', async () => {
    const { app } = await setupTenant();
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_client' });
  });

  it('returns invalid_grant when Toss FAILs', async () => {
    const { app, tenantId, clientSecret } = await setupTenant();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              resultType: 'FAIL',
              error: { reason: 'INVALID_AUTHORIZATION_CODE' },
            }),
          ),
      ),
    );
    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('returns unsupported_grant_type for unknown grants', async () => {
    const { app, tenantId, clientSecret } = await setupTenant();
    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({ grant_type: 'password' }),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'unsupported_grant_type' });
  });
});

describe('POST /oidc/token — refresh_token', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('round-trips a sealed refresh token (rotates AT, optionally rotates RT)', async () => {
    const { app, config, tenantId, clientSecret } = await setupTenant();
    const initialAt = 'h.eyJleHAiOjE5MDAwMDAwMDB9.s';
    const refreshedAt = 'h.eyJleHAiOjE5MDAwMDM2MDB9.s';

    // Phase 1: get an authorization_code response, capture the refresh_token
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.endsWith('/generate-token')) {
          return new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: {
                accessToken: initialAt,
                refreshToken: 'rt-original',
                tokenType: 'Bearer',
                expiresIn: 3600,
                scope: 'user_key',
              },
            }),
          );
        }
        if (url.endsWith('/login-me')) {
          return new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: { userKey: 1, scope: 'user_key', agreedTerms: [] },
            }),
          );
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );

    const enc = Buffer.from(`${tenantId}:${clientSecret}`).toString('base64');
    const res1 = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'auth_xxx' }),
    });
    expect(res1.status).toBe(200);
    const body1 = (await res1.json()) as Record<string, unknown>;
    const sealedRt = body1.refresh_token as string;
    expect(sealedRt).toMatch(/^aitc_/);

    // Phase 2: refresh_token grant. Toss may rotate RT; here we keep RT unrotated.
    vi.unstubAllGlobals();
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.endsWith('/refresh-token')) {
          return new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: {
                accessToken: refreshedAt,
                tokenType: 'Bearer',
                expiresIn: 3600,
                scope: 'user_key',
              },
            }),
          );
        }
        if (url.endsWith('/login-me')) {
          return new Response(
            JSON.stringify({
              resultType: 'SUCCESS',
              success: { userKey: 1, scope: 'user_key', agreedTerms: [] },
            }),
          );
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );

    const res2 = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${enc}`,
      },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: sealedRt }),
    });
    expect(res2.status).toBe(200);
    const body2 = (await res2.json()) as Record<string, unknown>;
    expect(body2.access_token as string).toMatch(/^aitc_/);

    const unsealed = unsealAccessToken({
      token: body2.access_token as string,
      masterKey: config.masterKey,
      sealingKeyVersionOf: () => 1,
    });
    expect(unsealed.tenant_id).toBe(tenantId);
    expect(unsealed.toss_access_token).toBe(refreshedAt);
    // Unrotated RT preserved
    expect(unsealed.toss_refresh_token).toBe('rt-original');
  });
});
