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
