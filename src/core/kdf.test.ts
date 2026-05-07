import { describe, expect, it } from 'vitest';
import { nodeKdf } from '../runtime/node-kdf.js';
import { equals, fromUtf8 } from './bytes.js';
import type { Kdf, KdfDeriveInput } from './kdf.js';
import { webCryptoKdf } from './kdf.js';

const IMPLS: Array<[string, Kdf]> = [
  ['nodeKdf', nodeKdf],
  ['webCryptoKdf', webCryptoKdf],
];

const BASE_INPUT: KdfDeriveInput = {
  secret: new Uint8Array(32).fill(0xab),
  salt: fromUtf8('a_1'),
  info: fromUtf8('ait/seal/v1'),
  hash: 'SHA-256',
  lengthBytes: 32,
};

describe.each(IMPLS)('%s', (_name, kdf) => {
  it('is deterministic for the same inputs', async () => {
    const k1 = await kdf.deriveBits(BASE_INPUT);
    const k2 = await kdf.deriveBits(BASE_INPUT);
    expect(equals(k1, k2)).toBe(true);
  });

  it('output is exactly lengthBytes long', async () => {
    const k = await kdf.deriveBits(BASE_INPUT);
    expect(k).toHaveLength(BASE_INPUT.lengthBytes);
  });

  it('different salt → different output', async () => {
    const k1 = await kdf.deriveBits({ ...BASE_INPUT, salt: fromUtf8('salt_a') });
    const k2 = await kdf.deriveBits({ ...BASE_INPUT, salt: fromUtf8('salt_b') });
    expect(equals(k1, k2)).toBe(false);
  });

  it('different info → different output', async () => {
    const k1 = await kdf.deriveBits({ ...BASE_INPUT, info: fromUtf8('info_a') });
    const k2 = await kdf.deriveBits({ ...BASE_INPUT, info: fromUtf8('info_b') });
    expect(equals(k1, k2)).toBe(false);
  });

  it('different secret → different output', async () => {
    const k1 = await kdf.deriveBits({ ...BASE_INPUT, secret: new Uint8Array(32).fill(0xab) });
    const k2 = await kdf.deriveBits({ ...BASE_INPUT, secret: new Uint8Array(32).fill(0xcd) });
    expect(equals(k1, k2)).toBe(false);
  });
});

describe('cross-impl byte equality', () => {
  it('nodeKdf and webCryptoKdf produce identical bytes for hard-coded vector', async () => {
    const nodeOut = await nodeKdf.deriveBits(BASE_INPUT);
    const wcOut = await webCryptoKdf.deriveBits(BASE_INPUT);
    expect(equals(nodeOut, wcOut)).toBe(true);
  });
});
