import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildAgent } from './client.js';
import { refreshToken } from './refresh-token.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

const successBody = {
  resultType: 'SUCCESS',
  success: {
    accessToken: 'new-access-token',
    refreshToken: 'new-refresh-token',
    tokenType: 'Bearer',
    expiresIn: 3600,
    scope: 'user_key',
  },
};

const successBodySameRT = {
  resultType: 'SUCCESS',
  success: {
    accessToken: 'new-access-token',
    tokenType: 'Bearer',
    expiresIn: 3600,
  },
};

const failBody = {
  resultType: 'FAIL',
  error: {
    reason: 'INVALID_REFRESH_TOKEN',
    description: 'The refresh token is invalid or expired.',
  },
};

describe('refreshToken', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns ok:true with new tokens on success', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(successBody), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await refreshToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      refreshToken: 'old-rt',
      referrer: 'DEFAULT',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.accessToken).toBe('new-access-token');
    }
  });

  it('returns ok:true when Toss does not rotate refresh token', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(successBodySameRT), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await refreshToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      refreshToken: 'old-rt',
      referrer: 'DEFAULT',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.refreshToken).toBeUndefined();
    }
  });

  it('returns ok:false with reason on fail', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(failBody), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await refreshToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      refreshToken: 'bad-rt',
      referrer: 'DEFAULT',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('INVALID_REFRESH_TOKEN');
    }
  });

  it('posts body with refreshToken and referrer', async () => {
    let capturedBody: unknown;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: unknown, init: { body?: string }) => {
        capturedBody = init.body ? JSON.parse(init.body) : undefined;
        return new Response(JSON.stringify(successBody), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    await refreshToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      refreshToken: 'my-rt',
      referrer: 'SANDBOX',
    });
    expect(capturedBody).toEqual({ refreshToken: 'my-rt', referrer: 'SANDBOX' });
  });
});
