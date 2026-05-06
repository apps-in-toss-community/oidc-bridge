import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pino from 'pino';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { ProbeItem } from '../cli/output.js';
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

describe('admin + session coexistence', () => {
  let dir: string;
  let storage: Storage;
  const stubSession = {
    async login() {
      return { kind: 'invalid_credentials' as const };
    },
    async logout() {},
    async validate() {
      return null;
    },
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-app-coexist-'));
    storage = createSqliteStorage({ path: join(dir, 'test.db') });
  });
  afterEach(async () => {
    await storage.close();
    rmSync(dir, { recursive: true, force: true });
  });

  function buildApp() {
    const svc = createService({ storage });
    return createApp({
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
      session: { service: stubSession },
    });
  }

  it('POST /admin/login returns 401 from session service (not from adminAuth) when no bearer', async () => {
    const app = buildApp();
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'x@y', password: 'wrong' }),
    });
    // The session service returns 401 with `error: invalid_credentials`.
    // adminAuth would return 401 with `error: unauthorized`. We want the
    // former — login must not require an admin bearer.
    expect(r.status).toBe(401);
    const body = (await r.json()) as { error: string };
    expect(body.error).toBe('invalid_credentials');
  });

  it('POST /admin/logout is also exempt from adminAuth', async () => {
    const app = buildApp();
    const r = await app.request('/admin/logout', { method: 'POST' });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { ok: boolean };
    expect(body.ok).toBe(true);
  });

  it('GET /admin/workspaces still requires admin bearer (regression guard)', async () => {
    const app = buildApp();
    const r = await app.request('/admin/workspaces');
    expect(r.status).toBe(401);
    const body = (await r.json()) as { error: string };
    expect(body.error).toBe('unauthorized');
  });
});

describe('Phase 8 wiring (observability + rate-limit + status)', () => {
  function captureLogger() {
    const logs: string[] = [];
    const stream = {
      write: (s: string) => {
        logs.push(s);
        return true;
      },
    } as unknown as NodeJS.WritableStream;
    return { logger: pino({}, stream), logs };
  }

  const stubProbes = async (): Promise<ProbeItem[]> => [
    { name: 'db', state: 'green', detail: 'ok' },
    { name: 'jwks', state: 'green', detail: 'ok' },
  ];

  it('GET /status returns 200 with version + build_sha (status-only opts)', async () => {
    const app = createApp({
      status: { version: '0.0.0-test', buildSha: 'testsha', probes: stubProbes },
    });
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    expect(r.status).toBe(200);
    const j = (await r.json()) as { version: string; build_sha: string };
    expect(j.version).toBe('0.0.0-test');
    expect(j.build_sha).toBe('testsha');
  });

  it('every response carries x-request-id when observability is on', async () => {
    const { logger } = captureLogger();
    const app = createApp({
      observability: { logger, ipHashSalt: 'salt' },
    });
    const r = await app.request('/healthz');
    expect(r.headers.get('x-request-id')).toMatch(/^[0-9a-f-]+$/);
  });

  it('emits one structured log line per request', async () => {
    const { logger, logs } = captureLogger();
    const app = createApp({
      observability: { logger, ipHashSalt: 'salt' },
    });
    await app.request('/healthz', { headers: { 'x-forwarded-for': '1.2.3.4' } });
    expect(logs).toHaveLength(1);
    const line = JSON.parse(logs[0] ?? '{}');
    expect(line.path).toBe('/healthz');
    expect(line.status).toBe(200);
    expect(line.ip_hash).toMatch(/^[0-9a-f]{16}$/);
    expect(typeof line.request_id).toBe('string');
  });

  it('/healthz is exempt from rate-limit (load balancer hammering)', async () => {
    const app = createApp({
      rateLimit: { enabled: true, ipPerMin: 1, appPerMin: 1 },
    });
    for (let i = 0; i < 10; i++) {
      const r = await app.request('/healthz', { headers: { 'x-forwarded-for': '1.1.1.1' } });
      expect(r.status).toBe(200);
    }
  });

  it('/status is exempt from rate-limit', async () => {
    const app = createApp({
      rateLimit: { enabled: true, ipPerMin: 1, appPerMin: 1 },
      status: { version: 'v', buildSha: 's', probes: stubProbes },
    });
    for (let i = 0; i < 5; i++) {
      const r = await app.request('/status', { headers: { 'x-forwarded-for': '1.1.1.1' } });
      expect(r.status).toBe(200);
    }
  });

  it('/oidc/* IS rate-limited (per-IP)', async () => {
    const app = createApp({
      rateLimit: { enabled: true, ipPerMin: 2, appPerMin: 1000 },
    });
    // /oidc/userinfo is not mounted (no oidc opts), so a 4xx is expected;
    // the point is that the 3rd request returns 429 instead of whatever
    // the route would return.
    const fire = () => app.request('/oidc/userinfo', { headers: { 'x-forwarded-for': '1.1.1.1' } });
    const r1 = await fire();
    const r2 = await fire();
    const r3 = await fire();
    expect(r1.status).not.toBe(429);
    expect(r2.status).not.toBe(429);
    expect(r3.status).toBe(429);
  });

  it('admin + session + observability + rate-limit + status all coexist', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-app-phase8-'));
    const storage = createSqliteStorage({ path: join(dir, 'test.db') });
    try {
      await storage.createUser({ id: 'user_a', email: 'a@x.com' });
      const svc = createService({ storage });
      const adminToken = (
        await svc.apiTokens.create({ actorUserId: 'user_a' }, { name: 'cli', scopes: ['admin'] })
      ).plaintext;
      const { logger, logs } = captureLogger();
      const stubSession = {
        async login() {
          return { kind: 'invalid_credentials' as const };
        },
        async logout() {},
        async validate() {
          return null;
        },
      };
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
        session: { service: stubSession },
        observability: { logger, ipHashSalt: 'salt' },
        rateLimit: { enabled: true, ipPerMin: 1000, appPerMin: 1000 },
        status: { version: 'v', buildSha: 's', probes: stubProbes },
      });

      // /healthz still works.
      const h = await app.request('/healthz');
      expect(h.status).toBe(200);

      // /status still works.
      const s = await app.request('/status', { headers: { accept: 'application/json' } });
      expect(s.status).toBe(200);

      // Admin auth still enforced (regression guard for #37).
      const a = await app.request('/admin/workspaces');
      expect(a.status).toBe(401);

      // Admin with bearer works.
      const a2 = await app.request('/admin/workspaces', {
        headers: { authorization: `Bearer ${adminToken}` },
      });
      expect(a2.status).toBe(200);

      // /admin/login (session) is exempt from admin bearer.
      const l = await app.request('/admin/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'x@y', password: 'wrong' }),
      });
      expect(l.status).toBe(401);
      expect(((await l.json()) as { error: string }).error).toBe('invalid_credentials');

      // Logs were emitted.
      expect(logs.length).toBeGreaterThan(0);
      // None of them contain raw client IPs (only ip_hash).
      for (const line of logs) {
        expect(line).not.toContain('"ip":');
      }
    } finally {
      await storage.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
