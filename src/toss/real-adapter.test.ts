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
});
