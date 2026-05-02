import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { createSqliteStorage } from '../storage/sqlite.js';
import { mountAdminRoutes } from './routes.js';
import { createService } from './service.js';

let dir: string;
let storage: Storage;
let token: string;

async function makeApp() {
  const svc = createService({ storage });
  const app = new Hono();
  mountAdminRoutes(app, {
    service: svc,
    masterKeyProvider: {
      async getKeyBytes() {
        return Buffer.alloc(32, 0xab);
      },
      async listVersions() {
        return [1];
      },
    },
    activeMasterKeyVersion: () => 1,
    stage: () => 'alpha',
  });
  return app;
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-routes-'));
  storage = createSqliteStorage({ path: join(dir, 'test.db') });
  await storage.createUser({ id: 'user_a', email: 'a@x.com' });
  const svc = createService({ storage });
  const r = await svc.apiTokens.create(
    { actorUserId: 'user_a' },
    { name: 'cli', scopes: ['admin'] },
  );
  token = r.plaintext;
});

afterEach(async () => {
  await storage.close();
  rmSync(dir, { recursive: true, force: true });
});

const auth = () => ({ authorization: `Bearer ${token}` });

async function readJson<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

describe('admin routes — workspaces', () => {
  it('POST /admin/workspaces creates', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    expect(res.status).toBe(201);
    const body = await readJson<Record<string, unknown>>(res);
    expect(body.name).toBe('first');
  });

  it('GET /admin/workspaces lists', async () => {
    const app = await makeApp();
    await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    const res = await app.request('/admin/workspaces', { headers: auth() });
    expect(res.status).toBe(200);
    const body = await readJson<Record<string, unknown>>(res);
    expect(body).toHaveLength(1);
  });

  it('PATCH /admin/workspaces/:id updates name', async () => {
    const app = await makeApp();
    const c = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    const id = (await readJson<{ id: string }>(c)).id;
    const res = await app.request(`/admin/workspaces/${id}`, {
      method: 'PATCH',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'renamed' }),
    });
    expect(res.status).toBe(200);
    const body = await readJson<Record<string, unknown>>(res);
    expect(body.name).toBe('renamed');
  });

  it('DELETE /admin/workspaces/:id removes', async () => {
    const app = await makeApp();
    const c = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'first' }),
    });
    const id = (await readJson<{ id: string }>(c)).id;
    const res = await app.request(`/admin/workspaces/${id}`, {
      method: 'DELETE',
      headers: auth(),
    });
    expect(res.status).toBe(204);
  });

  it('POST /admin/workspaces validates body (zod)', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ wrong: 'field' }),
    });
    expect(res.status).toBe(400);
  });
});

describe('admin routes — api_tokens', () => {
  it('POST /admin/api-tokens returns plaintext exactly once', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/api-tokens', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'second', scopes: ['admin'] }),
    });
    expect(res.status).toBe(201);
    const body = await readJson<{ plaintext: string; token: { id: string } }>(res);
    expect(body.plaintext.startsWith('tok_')).toBe(true);
    expect(body.token.id).toMatch(/^tok_/);
  });

  it('GET /admin/api-tokens does not return token_hash', async () => {
    const app = await makeApp();
    const res = await app.request('/admin/api-tokens', { headers: auth() });
    const body = await readJson<Array<Record<string, unknown>>>(res);
    for (const t of body) {
      expect(t.tokenHash).toBeUndefined();
      expect(t.token_hash).toBeUndefined();
    }
  });
});

describe('admin routes — apps', () => {
  async function bootstrap(app: Awaited<ReturnType<typeof makeApp>>) {
    const wsRes = await app.request('/admin/workspaces', {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'ws' }),
    });
    return (await readJson<{ id: string }>(wsRes)).id;
  }

  type CreateAppBody = {
    app: { id: string; mtlsPresent: boolean; ownershipStatus: string };
    clientSecret: string;
  };

  it('POST /admin/workspaces/:wsId/apps creates and returns plaintext secret once', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const res = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-1',
        displayTitle: 'My App',
        mtlsCertPem: '-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----',
        mtlsKeyPem: '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----',
        allowedOrigins: ['https://app.example.com'],
      }),
    });
    expect(res.status).toBe(201);
    const body = await readJson<CreateAppBody>(res);
    expect(body.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(body.app.mtlsPresent).toBe(true);
    expect(body.app.ownershipStatus).toBe('verified');
  });

  it('GET /admin/apps/:id never returns mTLS bytes', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const create = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-2',
        displayTitle: 'X',
        mtlsCertPem: 'cert',
        mtlsKeyPem: 'key',
        allowedOrigins: [],
      }),
    });
    const id = (await readJson<CreateAppBody>(create)).app.id;
    const res = await app.request(`/admin/apps/${id}`, { headers: auth() });
    const body = await readJson<Record<string, unknown>>(res);
    expect(body.mtlsPresent).toBe(true);
    expect(body.mtlsCertEnc).toBeUndefined();
    expect(body.mtlsKeyEnc).toBeUndefined();
    expect(body.mtls_cert_enc).toBeUndefined();
    expect(body.mtls_key_enc).toBeUndefined();
  });

  it('POST /admin/apps/:id/secrets/rotate returns a new plaintext', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const create = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-3',
        displayTitle: 'X',
        mtlsCertPem: 'c',
        mtlsKeyPem: 'k',
        allowedOrigins: [],
      }),
    });
    const id = (await readJson<CreateAppBody>(create)).app.id;
    const res = await app.request(`/admin/apps/${id}/secrets/rotate`, {
      method: 'POST',
      headers: auth(),
    });
    expect(res.status).toBe(200);
    const body = await readJson<{ clientSecret: string }>(res);
    expect(body.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('POST /admin/apps/:id/raw-tokens flips the toggle', async () => {
    const app = await makeApp();
    const wsId = await bootstrap(app);
    const create = await app.request(`/admin/workspaces/${wsId}/apps`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({
        appIdToss: 'mini-4',
        displayTitle: 'X',
        mtlsCertPem: 'c',
        mtlsKeyPem: 'k',
        allowedOrigins: [],
      }),
    });
    const id = (await readJson<CreateAppBody>(create)).app.id;
    const res = await app.request(`/admin/apps/${id}/raw-tokens`, {
      method: 'POST',
      headers: { ...auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ enabled: true }),
    });
    const body = await readJson<{ rawTokensEnabled: boolean }>(res);
    expect(body.rawTokensEnabled).toBe(true);
  });
});
