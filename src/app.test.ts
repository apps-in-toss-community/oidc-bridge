import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';

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
