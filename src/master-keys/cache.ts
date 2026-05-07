import type { MasterKeyProvider } from './provider.js';

export interface TtlCacheOptions {
  /** Default 6 hours. */
  ttlMs?: number;
  /** Override clock for testing. */
  now?: () => number;
}

const SIX_HOURS_MS = 6 * 60 * 60 * 1000;

interface Entry {
  bytes: Uint8Array;
  expiresAt: number;
}

export function withTtlCache(
  inner: MasterKeyProvider,
  opts: TtlCacheOptions = {},
): MasterKeyProvider {
  const ttl = opts.ttlMs ?? SIX_HOURS_MS;
  const now = opts.now ?? Date.now;
  const cache = new Map<number, Entry>();

  return {
    async getKeyBytes(version: number): Promise<Uint8Array> {
      const t = now();
      const entry = cache.get(version);
      if (entry && entry.expiresAt > t) {
        return entry.bytes;
      }
      const bytes = await inner.getKeyBytes(version);
      cache.set(version, { bytes, expiresAt: t + ttl });
      return bytes;
    },
    async listVersions(): Promise<number[]> {
      return inner.listVersions();
    },
  };
}
