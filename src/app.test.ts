import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import { createService } from './apps/service.js';
import type { Storage } from './storage/interface.js';
import { createSqliteStorage } from './storage/sqlite.js';

describe('GET /healthz', () => {
  it('returns ok', async () => {
    const app = createApp();
    const res = await app.request('/healthz');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });
});

describe('legacy /verify is gone', () => {
  it('returns 404 for POST /verify', async () => {
    const app = createApp();
    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationCode: 'x', referrer: 'SANDBOX' }),
    });
    expect(res.status).toBe(404);
  });
});

describe('createApp with admin', () => {
  let dir: string;
  let storage: Storage;
  let token: string;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-app-admin-'));
    storage = createSqliteStorage({ path: join(dir, 'test.db') });
    await storage.createUser({ id: 'user_a', email: 'a@x.com' });
    const svc = createService({ storage });
    token = (
      await svc.apiTokens.create({ actorUserId: 'user_a' }, { name: 'cli', scopes: ['admin'] })
    ).plaintext;
  });

  afterEach(async () => {
    await storage.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('mounts /admin/workspaces when admin opts are provided', async () => {
    const svc = createService({ storage });
    const app = createApp({
      admin: {
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
      },
    });
    const res = await app.request('/admin/workspaces', {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it('does not mount /admin/* without admin opts', async () => {
    const app = createApp();
    const res = await app.request('/admin/workspaces');
    expect(res.status).toBe(404);
  });
});

describe('createApp session-login mounting', () => {
  const stubService = {
    async login() {
      return { kind: 'invalid_credentials' as const };
    },
    async logout() {},
    async validate() {
      return null;
    },
  };

  it('does not mount /admin/login when session opts absent (flag-off)', async () => {
    const app = createApp();
    const r = await app.request('/admin/login', { method: 'POST' });
    expect(r.status).toBe(404);
  });

  it('mounts /admin/login when session opts supplied (flag-on)', async () => {
    const app = createApp({ session: { service: stubService } });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'x@y', password: 'wrong' }),
    });
    // Real service rejects → 401. Important is that the route exists, not 404.
    expect(r.status).toBe(401);
  });
});
