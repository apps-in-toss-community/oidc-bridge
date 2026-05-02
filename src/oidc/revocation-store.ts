import { createHash } from 'node:crypto';

export interface RevocationStore {
  revoke(input: { appId: string; token: string }): void;
  isRevoked(input: { appId: string; token: string }): boolean;
}

export function createInMemoryRevocationStore(): RevocationStore {
  const set = new Set<string>();
  const key = (appId: string, token: string): string =>
    createHash('sha256').update(`${appId} ${token}`).digest('hex');
  return {
    revoke({ appId, token }) {
      set.add(key(appId, token));
    },
    isRevoked({ appId, token }) {
      return set.has(key(appId, token));
    },
  };
}
