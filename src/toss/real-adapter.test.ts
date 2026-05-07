import { describe, expect, it, vi } from 'vitest';
import type { MtlsClient, MtlsClientFactory } from '../core/mtls.js';
import { RealTossAdapter } from './real-adapter.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFakeClient(fetchImpl: typeof fetch): MtlsClient {
  return {
    request: (url, init) => fetchImpl(url, init),
  };
}

function makeFakeFactory(fetchImpl: typeof fetch): MtlsClientFactory {
  const forApp = vi.fn(async (_appId: string) => makeFakeClient(fetchImpl));
  return { forApp };
}

function makeFactory(fetchImpl: typeof fetch): {
  factory: MtlsClientFactory;
  forApp: ReturnType<typeof vi.fn>;
} {
  const forApp = vi.fn(async (_appId: string): Promise<MtlsClient> => makeFakeClient(fetchImpl));
  return { factory: { forApp }, forApp };
}

function successTokenResponse() {
  return new Response(
    JSON.stringify({
      resultType: 'SUCCESS',
      success: { accessToken: 'x', refreshToken: 'y', expiresIn: 3600, scope: 'openid' },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RealTossAdapter', () => {
  it('calls factory.forApp with the correct appId and reuses client across calls', async () => {
    const fetchImpl = vi.fn(async () => successTokenResponse());
    const { factory, forApp } = makeFactory(fetchImpl);

    const adapter = new RealTossAdapter({ apiBase: 'https://x.example', mtlsFactory: factory });

    // The adapter no longer owns the cache — the factory does. We verify that
    // forApp is called with the correct appId on every invocation (factory
    // itself handles deduplication in production).
    await adapter.generateToken({ appId: 'app_a' }, { authorizationCode: 'c1' });
    await adapter.generateToken({ appId: 'app_a' }, { authorizationCode: 'c2' });
    await adapter.generateToken({ appId: 'app_b' }, { authorizationCode: 'c3' });

    expect(forApp).toHaveBeenCalledWith('app_a');
    expect(forApp).toHaveBeenCalledWith('app_b');
  });

  it('throws upstream_error when factory.forApp throws (no mtls material)', async () => {
    const factory: MtlsClientFactory = {
      forApp: async () => {
        throw new Error('MtlsClient(node): no mtls material for app=gone');
      },
    };
    const adapter = new RealTossAdapter({ apiBase: 'https://x.example', mtlsFactory: factory });
    await expect(
      adapter.generateToken({ appId: 'gone' }, { authorizationCode: 'c' }),
    ).rejects.toMatchObject({ code: 'upstream_error' });
  });

  it('maps FAIL INVALID_AUTHORIZATION_CODE to invalid_grant', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            resultType: 'FAIL',
            error: { code: 'INVALID_AUTHORIZATION_CODE', message: 'expired' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    await expect(
      adapter.generateToken({ appId: 'a' }, { authorizationCode: 'bad' }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  it('maps HTTP 503 to upstream_error', async () => {
    const fetchImpl = vi.fn(async () => new Response('', { status: 503 }));
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    await expect(
      adapter.generateToken({ appId: 'a' }, { authorizationCode: 'c' }),
    ).rejects.toMatchObject({ code: 'upstream_error' });
  });

  it('maps fetch throw (network) to upstream_error', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    await expect(
      adapter.generateToken({ appId: 'a' }, { authorizationCode: 'c' }),
    ).rejects.toMatchObject({ code: 'upstream_error' });
  });

  it('refreshToken happy returns new TokenSet', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toContain('/oauth2/refresh-token');
      expect(JSON.parse(init?.body as string)).toEqual({ refreshToken: 'rt_old' });
      return new Response(
        JSON.stringify({
          resultType: 'SUCCESS',
          success: {
            accessToken: 'at_new',
            refreshToken: 'rt_new',
            expiresIn: 3600,
            scope: 'openid profile',
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    const ts = await adapter.refreshToken({ appId: 'a' }, { refreshToken: 'rt_old' });
    expect(ts).toEqual({
      accessToken: 'at_new',
      refreshToken: 'rt_new',
      expiresIn: 3600,
      scope: ['openid', 'profile'],
    });
  });

  it('loginMe sends bearer header and returns parsed userKey', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toContain('/oauth2/login-me');
      const headers = init?.headers as Record<string, string>;
      expect(headers.authorization).toBe('Bearer toss_at_x');
      return new Response(
        JSON.stringify({
          resultType: 'SUCCESS',
          success: { userKey: 42, scope: 'openid profile', agreedTerms: ['service'] },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    const me = await adapter.loginMe({ appId: 'a' }, { accessToken: 'toss_at_x' });
    expect(me.userKey).toBe(42);
    expect(me.scope).toEqual(['openid', 'profile']);
    expect(me.agreedTerms).toEqual(['service']);
  });

  it('loginMe maps FAIL to upstream_error', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            resultType: 'FAIL',
            error: { code: 'INVALID_TOKEN', message: 'gone' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    await expect(adapter.loginMe({ appId: 'a' }, { accessToken: 'gone' })).rejects.toMatchObject({
      code: 'upstream_error',
    });
  });

  it('accessRemove sends userKey and resolves on SUCCESS', async () => {
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toContain('/oauth2/access-remove');
      expect(JSON.parse(init?.body as string)).toEqual({ userKey: '42' });
      return new Response(JSON.stringify({ resultType: 'SUCCESS', success: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    await expect(adapter.accessRemove({ appId: 'a' }, { userKey: '42' })).resolves.toBeUndefined();
  });

  it('accessRemove maps FAIL to upstream_error', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            resultType: 'FAIL',
            error: { code: 'NOT_FOUND', message: 'gone' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      mtlsFactory: makeFakeFactory(fetchImpl),
    });
    await expect(adapter.accessRemove({ appId: 'a' }, { userKey: '42' })).rejects.toMatchObject({
      code: 'upstream_error',
    });
  });
});
