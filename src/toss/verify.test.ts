import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyTossAuthorizationCode } from './verify.js';

function base64url(input: string): string {
  return Buffer.from(input, 'utf8')
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function makeJwt(payload: Record<string, unknown>): string {
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  return `${header}.${body}.signature-not-verified`;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('verifyTossAuthorizationCode', () => {
  const originalClientId = process.env.TOSS_CLIENT_ID;
  const originalSecret = process.env.TOSS_CLIENT_SECRET;
  const originalBase = process.env.TOSS_API_BASE;

  beforeEach(() => {
    process.env.TOSS_CLIENT_ID = 'test';
    process.env.TOSS_CLIENT_SECRET = 'test-secret';
    delete process.env.TOSS_API_BASE;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    if (originalClientId === undefined) delete process.env.TOSS_CLIENT_ID;
    else process.env.TOSS_CLIENT_ID = originalClientId;
    if (originalSecret === undefined) delete process.env.TOSS_CLIENT_SECRET;
    else process.env.TOSS_CLIENT_SECRET = originalSecret;
    if (originalBase === undefined) delete process.env.TOSS_API_BASE;
    else process.env.TOSS_API_BASE = originalBase;
  });

  it('returns server_misconfigured when env vars are missing', async () => {
    delete process.env.TOSS_CLIENT_ID;
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'SANDBOX',
    });
    expect(result).toEqual({
      ok: false,
      status: 500,
      error: 'server_misconfigured',
      description: expect.stringContaining('TOSS_CLIENT_ID'),
    });
  });

  it('calls Toss with Basic auth and JSON body at the configured base', async () => {
    process.env.TOSS_API_BASE = 'https://sandbox.example.invalid';
    const fetchMock = vi.fn(async () =>
      jsonResponse(200, {
        accessToken: makeJwt({ sub: 'user-1', exp: 1_900_000_000, scope: 'user_key user_name' }),
        tokenType: 'Bearer',
        expiresIn: 3599,
        scope: 'user_key user_name',
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_abc',
      referrer: 'SANDBOX',
    });

    expect(result).toEqual({
      ok: true,
      claims: {
        sub: 'user-1',
        provider: 'toss',
        claims: { scopes: ['user_key', 'user_name'] },
        tossAccessTokenExpiresAt: 1_900_000_000,
      },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const [url, init] = call;
    expect(url).toBe(
      'https://sandbox.example.invalid/api-partner/v1/apps-in-toss/user/oauth2/generate-token',
    );
    expect(init.method).toBe('POST');
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toBe(
      `Basic ${Buffer.from('test:test-secret').toString('base64')}`,
    );
    expect(headers['content-type']).toBe('application/json');
    expect(JSON.parse(init.body as string)).toEqual({
      authorizationCode: 'auth_abc',
      referrer: 'SANDBOX',
    });
  });

  it('maps Toss 401 to toss_rejected', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(401, { error: 'invalid_grant' })),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'bad',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({ ok: false, status: 401, error: 'toss_rejected' });
  });

  it('maps Toss 403 to upstream_error (treated as partner-creds issue, not a bad code)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(403, { error: 'forbidden' })),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({ ok: false, status: 502, error: 'upstream_error' });
  });

  it('maps Toss 5xx to upstream_error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(500, { error: 'internal' })),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({ ok: false, status: 502, error: 'upstream_error' });
  });

  it('maps fetch network errors to upstream_error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down');
      }),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({ ok: false, status: 502, error: 'upstream_error' });
  });

  it('rejects upstream responses without an accessToken', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(200, { tokenType: 'Bearer' })),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({
      ok: false,
      status: 502,
      error: 'invalid_upstream_response',
    });
  });

  it('rejects accessTokens that are not decodable JWTs with a sub', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => jsonResponse(200, { accessToken: 'not-a-jwt' })),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({
      ok: false,
      status: 502,
      error: 'invalid_upstream_response',
    });
  });

  it('falls back to expiresIn when the JWT has no exp', async () => {
    const now = 1_700_000_000;
    vi.spyOn(Date, 'now').mockReturnValue(now * 1000);
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse(200, {
          accessToken: makeJwt({ sub: 'user-2' }),
          expiresIn: 3600,
        }),
      ),
    );
    const result = await verifyTossAuthorizationCode({
      authorizationCode: 'auth_xxx',
      referrer: 'DEFAULT',
    });
    expect(result).toMatchObject({
      ok: true,
      claims: { sub: 'user-2', tossAccessTokenExpiresAt: now + 3600 },
    });
  });
});
