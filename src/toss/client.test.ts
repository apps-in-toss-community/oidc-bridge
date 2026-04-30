import { readFileSync } from 'node:fs';
import https from 'node:https';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { buildAgent, tossFetch } from './client.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

describe('buildAgent', () => {
  it('returns a https.Agent containing the supplied PEM bytes', () => {
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    expect(agent).toBeInstanceOf(https.Agent);
    const opts = (agent as unknown as { options: { cert?: string; key?: string } }).options;
    expect(opts.cert).toBe(certPem);
    expect(opts.key).toBe(keyPem);
  });
});

describe('tossFetch', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('passes the agent through dispatcher and returns parsed JSON', async () => {
    const fakeJson = { resultType: 'SUCCESS', success: { ok: true } };
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(fakeJson), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
      ),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    const out = await tossFetch({
      url: 'https://apps-in-toss-api.toss.im/x',
      method: 'POST',
      body: { hi: true },
      agent,
    });
    expect(out).toEqual(fakeJson);
  });

  it('throws temporarily_unavailable on network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNRESET');
      }),
    );
    const agent = buildAgent({ cert_pem: certPem, key_pem: keyPem });
    await expect(
      tossFetch({ url: 'https://x/x', method: 'POST', body: {}, agent }),
    ).rejects.toThrow(/temporarily_unavailable/);
  });
});
