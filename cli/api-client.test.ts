import { describe, expect, it, vi } from 'vitest';
import { createApiClient } from './api-client.js';

describe('createApiClient', () => {
  it('sends bearer + content-type and parses JSON', async () => {
    const fetchImpl = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
    );
    const c = createApiClient({ baseUrl: 'http://x', token: 'tok_x', fetchImpl });
    const out = await c.request<{ ok: boolean }>('GET', '/admin/workspaces');
    expect(out).toEqual({ ok: true });
    const headers = fetchImpl.mock.calls[0]![1]?.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer tok_x');
    expect(headers['content-type']).toBe('application/json');
  });

  it('throws on non-2xx', async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response('err', { status: 404 }));
    const c = createApiClient({ baseUrl: 'http://x', token: 't', fetchImpl });
    await expect(c.request('GET', '/x')).rejects.toThrow(/404/);
  });

  it('returns undefined on 204', async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () => new Response(null, { status: 204 }));
    const c = createApiClient({ baseUrl: 'http://x', token: 't', fetchImpl });
    expect(await c.request('DELETE', '/x')).toBeUndefined();
  });
});
