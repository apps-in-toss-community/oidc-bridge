import { describe, expect, it, vi } from 'vitest';
import { withTtlCache } from './cache.js';
import type { MasterKeyProvider } from './provider.js';

function makeMockProvider(): { provider: MasterKeyProvider; calls: () => number } {
  let calls = 0;
  const provider: MasterKeyProvider = {
    async getKeyBytes(v) {
      calls += 1;
      return Buffer.alloc(32, v);
    },
    async listVersions() {
      return [1, 2, 3];
    },
  };
  return { provider, calls: () => calls };
}

describe('withTtlCache', () => {
  it('memoizes getKeyBytes within the TTL', async () => {
    const m = makeMockProvider();
    const cached = withTtlCache(m.provider, { ttlMs: 1000 });
    const a = await cached.getKeyBytes(1);
    const b = await cached.getKeyBytes(1);
    expect(a.equals(b)).toBe(true);
    expect(m.calls()).toBe(1);
  });

  it('refetches after TTL expiry', async () => {
    vi.useFakeTimers();
    try {
      const m = makeMockProvider();
      const cached = withTtlCache(m.provider, { ttlMs: 60_000 });
      await cached.getKeyBytes(1);
      vi.advanceTimersByTime(60_001);
      await cached.getKeyBytes(1);
      expect(m.calls()).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not cache listVersions', async () => {
    let listCalls = 0;
    const counted: MasterKeyProvider = {
      async getKeyBytes(v) {
        return Buffer.alloc(32, v);
      },
      async listVersions() {
        listCalls += 1;
        return [1, 2, 3];
      },
    };
    const cached = withTtlCache(counted, { ttlMs: 60_000 });
    await cached.listVersions();
    await cached.listVersions();
    expect(listCalls).toBe(2);
  });

  it('caches different versions independently', async () => {
    const m = makeMockProvider();
    const cached = withTtlCache(m.provider, { ttlMs: 60_000 });
    await cached.getKeyBytes(1);
    await cached.getKeyBytes(2);
    await cached.getKeyBytes(1);
    expect(m.calls()).toBe(2);
  });
});
