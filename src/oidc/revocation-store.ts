import { fromUtf8, toHex } from '../core/bytes.js';
import type { Digest } from '../core/digest.js';
import { nodeDigest } from '../runtime/node-digest.js';

export interface RevocationStore {
  revoke(input: { appId: string; token: string }): Promise<void>;
  isRevoked(input: { appId: string; token: string }): Promise<boolean>;
}

export function createInMemoryRevocationStore(opts: { digest?: Digest } = {}): RevocationStore {
  const digest = opts.digest ?? nodeDigest;
  const set = new Set<string>();
  const key = async (appId: string, token: string): Promise<string> => {
    const h = await digest.digest('SHA-256', fromUtf8(`${appId} ${token}`));
    return toHex(h);
  };
  return {
    async revoke({ appId, token }) {
      set.add(await key(appId, token));
    },
    async isRevoked({ appId, token }) {
      return set.has(await key(appId, token));
    },
  };
}
