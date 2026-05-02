import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { createSqliteStorage } from '../storage/sqlite.js';
import { adminAuth } from './auth.js';
import { createService } from './service.js';

let dir: string;
let storage: Storage;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-auth-'));
  storage = createSqliteStorage({ path: join(dir, 'test.db') });
});

afterEach(async () => {
  await storage.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('adminAuth middleware', () => {
  async function bootstrap(): Promise<{ token: string; userId: string }> {
    await storage.createUser({ id: 'user_a', email: 'a@x.com' });
    const svc = createService({ storage });
    const r = await svc.apiTokens.create(
      { actorUserId: 'user_a' },
      { name: 'cli', scopes: ['admin'] },
    );
    return { token: r.plaintext, userId: 'user_a' };
  }

  function makeApp() {
    const svc = createService({ storage });
    const app = new Hono();
    app.use('/admin/*', adminAuth({ service: svc }));
    app.get('/admin/echo', (c) => {
      const user = c.get('user') as { id: string };
      return c.json({ id: user.id });
    });
    app.get('/admin/admin-only', adminAuth({ service: svc, requireScope: 'admin' }), (c) =>
      c.json({ ok: true }),
    );
    return app;
  }

  it('401 without Authorization header', async () => {
    const app = makeApp();
    const res = await app.request('/admin/echo');
    expect(res.status).toBe(401);
  });

  it('401 with malformed Authorization header', async () => {
    const app = makeApp();
    const res = await app.request('/admin/echo', { headers: { authorization: 'Basic xxx' } });
    expect(res.status).toBe(401);
  });

  it('401 with unknown bearer token', async () => {
    const app = makeApp();
    const res = await app.request('/admin/echo', {
      headers: { authorization: 'Bearer tok_unknown' },
    });
    expect(res.status).toBe(401);
  });

  it('200 with valid token; sets c.var.user', async () => {
    const { token } = await bootstrap();
    const app = makeApp();
    const res = await app.request('/admin/echo', {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ id: 'user_a' });
  });

  it('403 when scope is required but not present', async () => {
    await storage.createUser({ id: 'user_b', email: 'b@x.com' });
    const svc = createService({ storage });
    const r = await svc.apiTokens.create({ actorUserId: 'user_b' }, { name: 'cli', scopes: [] });
    const app = makeApp();
    const res = await app.request('/admin/admin-only', {
      headers: { authorization: `Bearer ${r.plaintext}` },
    });
    expect(res.status).toBe(403);
  });
});
