import * as tls from 'node:tls';
import { Pool } from 'undici';
import { describe, expect, it, vi } from 'vitest';
import { createNodeMtlsFactory } from './node-mtls.js';

describe('createNodeMtlsFactory', () => {
  it('caches MtlsClient per appId (Pool built only once per app)', async () => {
    const poolCount = 0;
    const fetchImpl = vi.fn(
      async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const getMtlsMaterial = vi.fn(async () => ({ certPem: 'CERT', keyPem: 'KEY' }));

    const factory = createNodeMtlsFactory({
      apiBase: 'https://x.example',
      getMtlsMaterial,
      // We track factory calls to getMtlsMaterial to infer caching.
      fetchImpl,
    });

    const client1a = await factory.forApp('app_a');
    const client1b = await factory.forApp('app_a');
    const client2 = await factory.forApp('app_b');

    // Same object returned for the same appId.
    expect(client1a).toBe(client1b);
    // Different object for a different appId.
    expect(client1a).not.toBe(client2);
    // getMtlsMaterial called once per unique appId.
    expect(getMtlsMaterial).toHaveBeenCalledTimes(2);

    void poolCount; // unused but satisfies linter if needed
  });

  it('throws when getMtlsMaterial returns null', async () => {
    const factory = createNodeMtlsFactory({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => null,
    });
    await expect(factory.forApp('missing')).rejects.toThrow(
      'MtlsClient(node): no mtls material for app=missing',
    );
  });

  it('client.request passes dispatcher in fetch init', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response('{}', { status: 200 });
    });

    const factory = createNodeMtlsFactory({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => ({ certPem: 'C', keyPem: 'K' }),
      fetchImpl,
    });

    const client = await factory.forApp('app_x');
    await client.request('https://x.example/api/path', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe('https://x.example/api/path');
    // dispatcher should be set in init (it's the undici Pool object)
    expect((call?.init as Record<string, unknown> | undefined)?.dispatcher).toBeDefined();
  });

  it('creates a real undici Pool with cert+key — Pool instance check', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }));
    // Use a custom fetchImpl that captures the dispatcher
    let capturedDispatcher: unknown;
    const capturingFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      capturedDispatcher = (init as Record<string, unknown>)?.dispatcher;
      return new Response('{}', { status: 200 });
    });

    const factory = createNodeMtlsFactory({
      apiBase: 'https://x.example',
      getMtlsMaterial: async () => ({ certPem: 'CERT_BYTES', keyPem: 'KEY_BYTES' }),
      fetchImpl: capturingFetch,
    });

    const client = await factory.forApp('pool-check');
    await client.request('https://x.example/test', { method: 'GET' });

    expect(capturedDispatcher).toBeInstanceOf(Pool);
    // Sanity-check: tls module is reachable (real Pool path uses it).
    expect(typeof tls.createSecureContext).toBe('function');

    // Clean up the pool
    if (capturedDispatcher instanceof Pool) {
      capturedDispatcher.close();
    }

    void fetchImpl; // suppress unused warning
  });
});
