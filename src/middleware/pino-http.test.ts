import { Hono } from 'hono';
import pino from 'pino';
import { describe, expect, it } from 'vitest';
import { pinoHttp } from './pino-http.js';
import { requestId } from './request-id.js';

function captureLogger(): { logger: pino.Logger; logs: string[] } {
  const logs: string[] = [];
  const stream = {
    write: (s: string) => {
      logs.push(s);
      return true;
    },
  } as unknown as NodeJS.WritableStream;
  const logger = pino({}, stream);
  return { logger, logs };
}

describe('pinoHttp', () => {
  it('emits one line per request with required fields', async () => {
    const { logger, logs } = captureLogger();
    const app = new Hono();
    app.use('*', requestId());
    app.use('*', pinoHttp({ logger, ipSalt: 'salt' }));
    app.get('/x', (c) => c.text('ok'));
    await app.request('/x', {
      headers: { 'user-agent': 'test/1.0', 'x-forwarded-for': '1.2.3.4' },
    });
    expect(logs).toHaveLength(1);
    const line = JSON.parse(logs[0] ?? '{}');
    expect(line.method).toBe('GET');
    expect(line.path).toBe('/x');
    expect(line.status).toBe(200);
    expect(typeof line.latency_ms).toBe('number');
    expect(line.user_agent).toBe('test/1.0');
    expect(typeof line.request_id).toBe('string');
    expect(line.ip_hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it('does not log the request body', async () => {
    const { logger, logs } = captureLogger();
    const app = new Hono();
    app.use('*', requestId());
    app.use('*', pinoHttp({ logger, ipSalt: 'salt' }));
    app.post('/x', async (c) => {
      await c.req.text();
      return c.text('ok');
    });
    await app.request('/x', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'SUPER_SECRET_VALUE',
    });
    expect(logs[0]).not.toContain('SUPER_SECRET_VALUE');
  });

  it('different IPs hash to different ip_hash values', async () => {
    const { logger, logs } = captureLogger();
    const app = new Hono();
    app.use('*', requestId());
    app.use('*', pinoHttp({ logger, ipSalt: 'salt' }));
    app.get('/x', (c) => c.text('ok'));
    await app.request('/x', { headers: { 'x-forwarded-for': '1.2.3.4' } });
    await app.request('/x', { headers: { 'x-forwarded-for': '5.6.7.8' } });
    const a = JSON.parse(logs[0] ?? '{}').ip_hash;
    const b = JSON.parse(logs[1] ?? '{}').ip_hash;
    expect(a).not.toBe(b);
  });

  it('same IP + same salt → same hash (deterministic)', async () => {
    const { logger, logs } = captureLogger();
    const app = new Hono();
    app.use('*', requestId());
    app.use('*', pinoHttp({ logger, ipSalt: 'fixed-salt' }));
    app.get('/x', (c) => c.text('ok'));
    await app.request('/x', { headers: { 'x-forwarded-for': '1.2.3.4' } });
    await app.request('/x', { headers: { 'x-forwarded-for': '1.2.3.4' } });
    const a = JSON.parse(logs[0] ?? '{}').ip_hash;
    const b = JSON.parse(logs[1] ?? '{}').ip_hash;
    expect(a).toBe(b);
  });
});
