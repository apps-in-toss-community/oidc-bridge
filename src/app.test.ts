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

describe('POST /verify', () => {
  const validBody = { authorizationCode: 'auth_xxx', referrer: 'SANDBOX' };

  async function post(body: unknown): Promise<Response> {
    const app = createApp();
    return app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    });
  }

  it('rejects non-JSON body with invalid_request', async () => {
    const res = await post('not-json');
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_request' });
  });

  it('rejects missing authorizationCode', async () => {
    const res = await post({ referrer: 'DEFAULT' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'invalid_request' });
  });

  it('rejects empty authorizationCode', async () => {
    const res = await post({ authorizationCode: '', referrer: 'DEFAULT' });
    expect(res.status).toBe(400);
  });

  it('rejects invalid referrer values', async () => {
    const res = await post({ authorizationCode: 'auth_xxx', referrer: 'PRODUCTION' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('referrer'),
    });
  });

  it('accepts DEFAULT and SANDBOX referrers', async () => {
    for (const referrer of ['DEFAULT', 'SANDBOX'] as const) {
      const res = await post({ ...validBody, referrer });
      // Stubbed verifier returns 501 until the real implementation lands;
      // the important assertion is that we got past the request-validation
      // layer (i.e. status is not 400).
      expect(res.status).not.toBe(400);
    }
  });

  it('returns 501 not_implemented from the stub verifier', async () => {
    const res = await post(validBody);
    expect(res.status).toBe(501);
    expect(await res.json()).toMatchObject({ error: 'not_implemented' });
  });
});
