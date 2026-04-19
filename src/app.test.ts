import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
  const originalClientId = process.env.TOSS_CLIENT_ID;
  const originalSecret = process.env.TOSS_CLIENT_SECRET;

  beforeEach(() => {
    process.env.TOSS_CLIENT_ID = 'test';
    process.env.TOSS_CLIENT_SECRET = 'test-secret';
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (originalClientId === undefined) delete process.env.TOSS_CLIENT_ID;
    else process.env.TOSS_CLIENT_ID = originalClientId;
    if (originalSecret === undefined) delete process.env.TOSS_CLIENT_SECRET;
    else process.env.TOSS_CLIENT_SECRET = originalSecret;
  });

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

  it('rejects missing referrer', async () => {
    const res = await post({ authorizationCode: 'auth_xxx' });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: 'invalid_request',
      error_description: expect.stringContaining('referrer'),
    });
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

  it('returns 500 server_misconfigured when Toss credentials are missing', async () => {
    delete process.env.TOSS_CLIENT_ID;
    const res = await post(validBody);
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: 'server_misconfigured' });
  });

  it('returns 401 when Toss rejects the authorizationCode', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ error: 'invalid_grant' }), {
            status: 401,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const res = await post(validBody);
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: 'invalid_code' });
  });

  it('returns verified claims on success', async () => {
    const base64url = (s: string) =>
      Buffer.from(s, 'utf8')
        .toString('base64')
        .replace(/=+$/, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    const jwt = `${base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))}.${base64url(
      JSON.stringify({ sub: 'user-42', exp: 1_900_000_000, scope: 'user_key' }),
    )}.sig`;

    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              accessToken: jwt,
              tokenType: 'Bearer',
              expiresIn: 3599,
              scope: 'user_key',
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          ),
      ),
    );

    const res = await post(validBody);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      sub: 'user-42',
      provider: 'toss',
      claims: { scopes: ['user_key'] },
      tossAccessTokenExpiresAt: 1_900_000_000,
    });
  });
});
