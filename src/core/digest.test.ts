import { describe, expect, it } from 'vitest';
import { nodeDigest } from '../runtime/node-digest.js';
import { equals, fromUtf8, toHex } from './bytes.js';
import type { Digest } from './digest.js';
import { webCryptoDigest } from './digest.js';

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

describe.each([
  ['nodeDigest', nodeDigest],
  ['webCryptoDigest', webCryptoDigest],
] as [string, Digest][])('%s', (_name, digest) => {
  it('SHA-256 of empty input matches known vector', async () => {
    const result = await digest.digest('SHA-256', new Uint8Array(0));
    expect(toHex(result)).toBe(EMPTY_SHA256);
  });

  it('SHA-256 of "abc" matches known vector', async () => {
    const result = await digest.digest('SHA-256', fromUtf8('abc'));
    expect(toHex(result)).toBe(ABC_SHA256);
  });

  it('output length is exactly 32 bytes', async () => {
    const result = await digest.digest('SHA-256', fromUtf8('anything'));
    expect(result.length).toBe(32);
  });

  it('different inputs produce different outputs', async () => {
    const a = await digest.digest('SHA-256', fromUtf8('hello'));
    const b = await digest.digest('SHA-256', fromUtf8('world'));
    expect(equals(a, b)).toBe(false);
  });
});

it('nodeDigest and webCryptoDigest produce identical bytes', async () => {
  const input = fromUtf8('cross-impl test vector 🔑');
  const nodeResult = await nodeDigest.digest('SHA-256', input);
  const webResult = await webCryptoDigest.digest('SHA-256', input);
  expect(equals(nodeResult, webResult)).toBe(true);
});
