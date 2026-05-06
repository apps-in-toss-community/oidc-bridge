import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import type { ProbeItem } from '../../cli/output.js';
import { mountStatusRoute } from './route.js';

const probesStub = async (): Promise<ProbeItem[]> => [
  { name: 'db', state: 'green', detail: 'ok' },
  { name: 'jwks', state: 'green', detail: 'ok' },
];

describe('/status route', () => {
  it('returns JSON when Accept: application/json', async () => {
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: '1.2.3', buildSha: 'abc1234', probes: probesStub }));
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('application/json');
    expect(r.headers.get('cache-control')).toContain('no-store');
    const j = (await r.json()) as Record<string, unknown>;
    expect(j.version).toBe('1.2.3');
    expect(j.build_sha).toBe('abc1234');
    expect(j.status).toBe('green');
    expect(j.items).toHaveLength(2);
  });

  it('returns HTML by default', async () => {
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: '1.2.3', buildSha: 'abc1234', probes: probesStub }));
    const r = await app.request('/status');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/html');
    expect(r.headers.get('cache-control')).toContain('no-store');
    const body = await r.text();
    expect(body).toContain('1.2.3');
    expect(body).toContain('abc1234');
    expect(body).toContain('db');
    expect(body).toContain('jwks');
  });

  it('?format=json forces JSON', async () => {
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: '1.2.3', buildSha: 'abc1234', probes: probesStub }));
    const r = await app.request('/status?format=json');
    expect(r.headers.get('content-type')).toContain('application/json');
  });

  it('overall is worst-of', async () => {
    const probes = async (): Promise<ProbeItem[]> => [
      { name: 'db', state: 'green', detail: 'ok' },
      { name: 'jwks', state: 'red', detail: 'broken' },
    ];
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: '1', buildSha: 'a', probes }));
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    const j = (await r.json()) as { status: string };
    expect(j.status).toBe('red');
  });

  it('worst-of yellow when any yellow + green', async () => {
    const probes = async (): Promise<ProbeItem[]> => [
      { name: 'db', state: 'green', detail: 'ok' },
      { name: 'last-healthz', state: 'yellow', detail: 'never' },
    ];
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: '1', buildSha: 'a', probes }));
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    const j = (await r.json()) as { status: string };
    expect(j.status).toBe('yellow');
  });

  it('escapes HTML in probe details to prevent XSS', async () => {
    const probes = async (): Promise<ProbeItem[]> => [
      { name: 'db', state: 'red', detail: '<script>alert(1)</script>' },
    ];
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: 'v', buildSha: 's', probes }));
    const r = await app.request('/status');
    const body = await r.text();
    expect(body).not.toContain('<script>alert(1)</script>');
    expect(body).toContain('&lt;script&gt;');
  });
});
