import bcrypt from 'bcryptjs';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import type { LoginResult, SessionService } from '../sessions/service.js';
import type { Session } from '../sessions/types.js';
import { mountSessionRoute } from './session-route.js';

interface TestAppOpts {
  enabled: boolean;
  passwordHash: string | null;
}

function buildTestApp(opts: TestAppOpts) {
  const sessions = new Map<string, Session>();
  const service: SessionService = {
    async login(email, password): Promise<LoginResult> {
      if (email !== 'a@b') return { kind: 'invalid_credentials' };
      if (opts.passwordHash === null) return { kind: 'no_password_set' };
      const ok = await bcrypt.compare(password, opts.passwordHash);
      if (!ok) return { kind: 'invalid_credentials' };
      const id = 'sid_test';
      const session: Session = {
        id,
        userId: 'u_1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60_000),
      };
      sessions.set(id, session);
      return { kind: 'ok', session };
    },
    async logout(id) {
      sessions.delete(id);
    },
    async validate(id) {
      return sessions.get(id) ?? null;
    },
  };
  const app = new Hono();
  if (opts.enabled) {
    app.route('/', mountSessionRoute({ service }));
  }
  return { app, sessions };
}

describe('session-route flag-gating', () => {
  it('flag off: POST /admin/login returns 404', async () => {
    const { app } = buildTestApp({ enabled: false, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 's' }),
    });
    expect(r.status).toBe(404);
  });

  it('flag off: POST /admin/logout returns 404', async () => {
    const { app } = buildTestApp({ enabled: false, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/logout', { method: 'POST' });
    expect(r.status).toBe(404);
  });
});

describe('session-route happy path', () => {
  it('valid creds: 200 + Set-Cookie with __Host-bridge_session', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 's' }),
    });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true });
    const cookie = r.headers.get('set-cookie');
    expect(cookie).toContain('__Host-bridge_session=sid_test');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/');
  });

  it('logout clears the cookie and revokes the session', async () => {
    const { app, sessions } = buildTestApp({
      enabled: true,
      passwordHash: bcrypt.hashSync('s', 4),
    });
    const login = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 's' }),
    });
    expect(login.status).toBe(200);
    expect(sessions.size).toBe(1);
    const sentCookie = login.headers.get('set-cookie') ?? '';
    const justCookiePair = sentCookie.split(';')[0] ?? '';
    const r = await app.request('/admin/logout', {
      method: 'POST',
      headers: { cookie: justCookiePair },
    });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ ok: true });
    expect(r.headers.get('set-cookie')).toContain('Max-Age=0');
    expect(sessions.size).toBe(0);
  });

  it('logout with no cookie still returns 200 (idempotent)', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/logout', { method: 'POST' });
    expect(r.status).toBe(200);
    expect(r.headers.get('set-cookie')).toContain('Max-Age=0');
  });
});

describe('session-route error paths', () => {
  it('wrong password: 401 invalid_credentials, no Set-Cookie', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 'wrong' }),
    });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'invalid_credentials' });
    expect(r.headers.get('set-cookie')).toBeNull();
  });

  it('unknown user: 401 invalid_credentials (no enumeration)', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@b', password: 'whatever' }),
    });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'invalid_credentials' });
  });

  it('user with no password_hash: 401 no_password_set', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: null });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 'anything' }),
    });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'no_password_set' });
  });

  it('missing body fields: 400 invalid_request', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: 'invalid_request' });
  });

  it('non-JSON body: 400 invalid_request', async () => {
    const { app } = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: 'invalid_request' });
  });
});
