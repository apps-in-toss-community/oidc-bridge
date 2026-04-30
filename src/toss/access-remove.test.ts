import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { removeByAccessToken } from './access-remove.js';
import { buildAgent } from './client.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

const successBody = {
  resultType: 'SUCCESS',
  success: { removed: true },
};

const failBody = {
  resultType: 'FAIL',
  error: {
    reason: 'TOKEN_NOT_FOUND',
    description: 'The access token was not found.',
  },
};

describe('removeByAccessToken', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns ok:true on success', async () => {
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
    const result = await removeByAccessToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      tossAccessToken: 'valid-at',
    });
    expect(result.ok).toBe(true);
  });

  it('returns ok:false on fail (caller maps to RFC 7009 always-200)', async () => {
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
    const result = await removeByAccessToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      tossAccessToken: 'unknown-at',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('TOKEN_NOT_FOUND');
    }
  });

  it('posts body with accessToken', async () => {
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
    await removeByAccessToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      tossAccessToken: 'my-at',
    });
    expect(capturedBody).toEqual({ accessToken: 'my-at' });
  });
});
