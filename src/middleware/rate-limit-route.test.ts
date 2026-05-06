import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { rateLimit } from './rate-limit-route.js';

describe('rateLimit middleware', () => {
  it('allows up to ip limit then 429', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 2, appPerMin: 1000, enabled: true }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = () =>
      app.request('/oidc/token', {
        method: 'POST',
        headers: {
          'x-forwarded-for': '1.2.3.4',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: 'client_id=app_a',
      });
    expect((await fire()).status).toBe(200);
    expect((await fire()).status).toBe(200);
    const r = await fire();
    expect(r.status).toBe(429);
    expect(await r.json()).toMatchObject({ error: 'rate_limited' });
    expect(r.headers.get('retry-after')).toBe('60');
  });

  it('returns 429 when app limit exceeded even if IP limit ok', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1000, appPerMin: 1, enabled: true }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = (ip: string) =>
      app.request('/oidc/token', {
        method: 'POST',
        headers: { 'x-forwarded-for': ip, 'content-type': 'application/x-www-form-urlencoded' },
        body: 'client_id=app_a',
      });
    expect((await fire('1.1.1.1')).status).toBe(200);
    expect((await fire('2.2.2.2')).status).toBe(429);
  });

  it('disabled by env: never rate-limits', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1, appPerMin: 1, enabled: false }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = () =>
      app.request('/oidc/token', { method: 'POST', headers: { 'x-forwarded-for': '1.1.1.1' } });
    for (let i = 0; i < 5; i++) {
      expect((await fire()).status).toBe(200);
    }
  });

  it('falls back to "unknown" appId when body has no client_id', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1000, appPerMin: 1, enabled: true }));
    app.get('/oidc/userinfo', (c) => c.text('ok'));
    const fire = (ip: string) =>
      app.request('/oidc/userinfo', { headers: { 'x-forwarded-for': ip } });
    expect((await fire('1.1.1.1')).status).toBe(200);
    // Both share appId="unknown" → second hits the per-app limit.
    expect((await fire('2.2.2.2')).status).toBe(429);
  });

  it('preserves the body for downstream handlers (form)', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 100, appPerMin: 100, enabled: true }));
    app.post('/oidc/token', async (c) => {
      const form = await c.req.parseBody();
      return c.json({ client_id: form.client_id });
    });
    const r = await app.request('/oidc/token', {
      method: 'POST',
      headers: {
        'x-forwarded-for': '1.1.1.1',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: 'client_id=preserve_me',
    });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ client_id: 'preserve_me' });
  });

  it('preserves the body for downstream handlers (json)', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 100, appPerMin: 100, enabled: true }));
    app.post('/oidc/token', async (c) => {
      const json = await c.req.json();
      return c.json({ client_id: json.client_id });
    });
    const r = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'x-forwarded-for': '1.1.1.1', 'content-type': 'application/json' },
      body: JSON.stringify({ client_id: 'json_app' }),
    });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ client_id: 'json_app' });
  });

  it('extracts client_id from JSON body for per-app rate limiting', async () => {
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1000, appPerMin: 1, enabled: true }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = (ip: string) =>
      app.request('/oidc/token', {
        method: 'POST',
        headers: { 'x-forwarded-for': ip, 'content-type': 'application/json' },
        body: JSON.stringify({ client_id: 'shared_app' }),
      });
    expect((await fire('1.1.1.1')).status).toBe(200);
    expect((await fire('2.2.2.2')).status).toBe(429);
  });
});
