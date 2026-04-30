import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildAgent } from './client.js';
import { loginMe } from './login-me.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');
const successFixture = JSON.parse(
  readFileSync('src/__fixtures__/toss-login-me.success.json', 'utf8'),
);
const failFixture = JSON.parse(readFileSync('src/__fixtures__/toss-login-me.fail.json', 'utf8'));

describe('loginMe', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns ok:true with userKey on success', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(successFixture), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await loginMe({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      tossAccessToken: 'test-access-token',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.userKey).toBe(4200000000001);
    }
  });

  it('returns ok:false with reason on fail', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(failFixture), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const result = await loginMe({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      tossAccessToken: 'expired-token',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('ACCESS_TOKEN_EXPIRED');
    }
  });

  it('sends GET request with Bearer authorization header', async () => {
    let capturedMethod: string | undefined;
    let capturedAuth: string | undefined;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: unknown, init: { method?: string; headers?: Record<string, string> }) => {
        capturedMethod = init.method;
        capturedAuth = init.headers?.authorization;
        return new Response(JSON.stringify(successFixture), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    await loginMe({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      tossAccessToken: 'my-token',
    });
    expect(capturedMethod).toBe('GET');
    expect(capturedAuth).toBe('Bearer my-token');
  });
});
