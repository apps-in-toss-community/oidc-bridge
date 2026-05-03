import { describe, expect, it, vi } from 'vitest';
import { RealTossAdapter } from './real-adapter.js';

describe('RealTossAdapter', () => {
  it('builds one dispatcher per appId and reuses it', async () => {
    const buildDispatcher = vi.fn(() => ({ marker: Math.random() }));
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            resultType: 'SUCCESS',
            success: { accessToken: 'x', refreshToken: 'y', expiresIn: 3600, scope: 'openid' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => ({ certPem: 'CERT', keyPem: 'KEY' }),
      fetchImpl,
      buildDispatcher,
    });

    await adapter.generateToken({ appId: 'app_a' }, { authorizationCode: 'c1' });
    await adapter.generateToken({ appId: 'app_a' }, { authorizationCode: 'c2' });
    await adapter.generateToken({ appId: 'app_b' }, { authorizationCode: 'c3' });

    expect(buildDispatcher).toHaveBeenCalledTimes(2);
  });

  it('throws upstream_error when app has no mtls material', async () => {
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => null,
      fetchImpl: async () => new Response('', { status: 200 }),
      buildDispatcher: () => ({}),
    });
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
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
      buildDispatcher: () => ({}),
    });
    await expect(
      adapter.generateToken({ appId: 'a' }, { authorizationCode: 'bad' }),
    ).rejects.toMatchObject({ code: 'invalid_grant' });
  });

  it('maps HTTP 503 to upstream_error', async () => {
    const fetchImpl = vi.fn(async () => new Response('', { status: 503 }));
    const adapter = new RealTossAdapter({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
      buildDispatcher: () => ({}),
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
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
      buildDispatcher: () => ({}),
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
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
      buildDispatcher: () => ({}),
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
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
      buildDispatcher: () => ({}),
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
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
      buildDispatcher: () => ({}),
    });
    await expect(adapter.loginMe({ appId: 'a' }, { accessToken: 'gone' })).rejects.toMatchObject({
      code: 'upstream_error',
    });
  });
});
