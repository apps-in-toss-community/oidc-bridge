import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildAgent } from './client.js';
import { generateToken } from './generate-token.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');
const successFixture = JSON.parse(
  readFileSync('src/__fixtures__/toss-generate-token.success.json', 'utf8'),
);
const failFixture = JSON.parse(
  readFileSync('src/__fixtures__/toss-generate-token.fail.json', 'utf8'),
);

describe('generateToken', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns ok:true with token data on success', async () => {
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
    const result = await generateToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      authorizationCode: 'test-code-123',
      referrer: 'DEFAULT',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({ accessToken: expect.any(String) });
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
    const result = await generateToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      authorizationCode: 'bad-code',
      referrer: 'DEFAULT',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('INVALID_AUTHORIZATION_CODE');
    }
  });

  it('posts body with authorizationCode and referrer', async () => {
    let capturedBody: unknown;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_url: unknown, init: { body?: string }) => {
        capturedBody = init.body ? JSON.parse(init.body) : undefined;
        return new Response(JSON.stringify(successFixture), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    await generateToken({
      apiBase: 'https://apps-in-toss-api.toss.im',
      agent,
      authorizationCode: 'my-code',
      referrer: 'SANDBOX',
    });
    expect(capturedBody).toEqual({ authorizationCode: 'my-code', referrer: 'SANDBOX' });
  });
});
