import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { adminAuth } from './auth.js';

function buildApp(): Hono {
  const app = new Hono();
  app.use('*', adminAuth('correct-token'));
  app.get('/probe', (c) => c.json({ ok: true }));
  return app;
}

describe('adminAuth', () => {
  it('returns 401 when authorization header is missing', async () => {
    const res = await buildApp().request('/probe');
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_token' });
  });

  it('returns 401 when scheme is not Bearer', async () => {
    const res = await buildApp().request('/probe', {
      headers: { authorization: 'Basic xyz' },
    });
    expect(res.status).toBe(401);
  });

  it('returns 401 when token is wrong', async () => {
    const res = await buildApp().request('/probe', {
      headers: { authorization: 'Bearer wrong' },
    });
    expect(res.status).toBe(401);
  });

  it('returns 401 when token is wrong and same length as expected', async () => {
    // Same length as 'correct-token' (13 chars), tests the timingSafeEqual path
    const res = await buildApp().request('/probe', {
      headers: { authorization: 'Bearer wrongxyz12345' },
    });
    expect(res.status).toBe(401);
  });

  it('returns 401 when Bearer scheme has empty token', async () => {
    const res = await buildApp().request('/probe', { headers: { authorization: 'Bearer   ' } });
    expect(res.status).toBe(401);
  });

  it('passes through to next handler when token matches', async () => {
    const res = await buildApp().request('/probe', {
      headers: { authorization: 'Bearer correct-token' },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});
