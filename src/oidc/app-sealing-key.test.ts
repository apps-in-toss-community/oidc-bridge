import { describe, expect, it } from 'vitest';
import { deriveSealingKey } from '../master-keys/index.js';
import { createAppSealingKeyResolver } from './app-sealing-key.js';

describe('createAppSealingKeyResolver', () => {
  it('derives the same key as deriveSealingKey for the matching version', async () => {
    const masterV1 = Buffer.alloc(32, 1);
    const masterV2 = Buffer.alloc(32, 2);
    const provider = {
      async getKeyBytes(version: number) {
        if (version === 1) return masterV1;
        if (version === 2) return masterV2;
        throw new Error('no such version');
      },
      async listVersions() {
        return [1, 2];
      },
    };
    const resolver = createAppSealingKeyResolver({ provider });
    const expected = deriveSealingKey({ masterKey: masterV1, appId: 'app_x' });
    const got = await resolver({ appId: 'app_x', sealingKeyVersion: 1 });
    expect(got.equals(expected)).toBe(true);
  });

  it('throws when provider does not have the version', async () => {
    const provider = {
      async getKeyBytes() {
        throw new Error('NOT_FOUND');
      },
      async listVersions() {
        return [1];
      },
    };
    const resolver = createAppSealingKeyResolver({ provider });
    await expect(resolver({ appId: 'app_x', sealingKeyVersion: 99 })).rejects.toThrow(/NOT_FOUND/);
  });
});
