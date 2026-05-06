import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { requestId } from './request-id.js';

describe('requestId middleware', () => {
  it('uses inbound X-Request-Id when valid', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId') ?? ''));
    const r = await app.request('/', { headers: { 'x-request-id': 'abc.123' } });
    expect(await r.text()).toBe('abc.123');
    expect(r.headers.get('x-request-id')).toBe('abc.123');
  });

  it('generates UUID when no inbound header', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId') ?? ''));
    const r = await app.request('/');
    const echoed = await r.text();
    expect(echoed).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(r.headers.get('x-request-id')).toBe(echoed);
  });

  it('rejects malformed inbound id (would allow log injection)', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId') ?? ''));
    // Spaces / quotes / brackets are valid HTTP header chars but unsafe to log
    // inline (they break log-line parsing). The middleware must replace them
    // with a fresh UUID rather than echo them.
    const r = await app.request('/', { headers: { 'x-request-id': 'a b"c]' } });
    const echoed = await r.text();
    expect(echoed).not.toBe('a b"c]');
    expect(echoed).toMatch(/^[0-9a-f-]+$/);
  });

  it('rejects inbound id over 128 chars', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId') ?? ''));
    const r = await app.request('/', { headers: { 'x-request-id': 'a'.repeat(129) } });
    const echoed = await r.text();
    expect(echoed).not.toBe('a'.repeat(129));
  });
});
