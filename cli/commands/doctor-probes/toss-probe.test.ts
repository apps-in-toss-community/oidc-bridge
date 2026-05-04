import { describe, expect, it, vi } from 'vitest';
import { runTossProbe } from './toss-probe.js';

const stubDispatcher = () => ({});

describe('runTossProbe', () => {
  it('yellow when no cert/key provided (skip)', async () => {
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: undefined,
      keyPem: undefined,
    });
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('no sandbox cert');
  });

  it('green when adapter.loginMe returns SUCCESS', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            resultType: 'SUCCESS',
            success: { userKey: 1, scope: 'openid', agreedTerms: [] },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'doctor_at',
      fetchImpl,
      buildDispatcher: stubDispatcher,
    });
    expect(r.state).toBe('green');
    expect(r.detail).toContain('SUCCESS');
  });

  it('green when adapter.loginMe returns FAIL with INVALID_TOKEN (handshake worked)', async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            resultType: 'FAIL',
            error: { code: 'INVALID_TOKEN', message: 'fake AT' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    );
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'fake_at',
      fetchImpl,
      buildDispatcher: stubDispatcher,
    });
    expect(r.state).toBe('green');
    expect(r.detail).toContain('handshake');
  });

  it('red when adapter.loginMe throws upstream_error (network or TLS fail)', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error('connect ECONNREFUSED');
    });
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'fake_at',
      fetchImpl,
      buildDispatcher: stubDispatcher,
    });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('ECONNREFUSED');
  });

  it('red on HTTP 5xx from Toss', async () => {
    const fetchImpl = vi.fn(async () => new Response('upstream error', { status: 503 }));
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'fake_at',
      fetchImpl,
      buildDispatcher: stubDispatcher,
    });
    expect(r.state).toBe('red');
  });
});
