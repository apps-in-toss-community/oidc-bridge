import { describe, expect, it } from 'vitest';
import { nodeRandom } from '../runtime/node-random.js';
import { webCryptoRandom } from './random.js';

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

describe.each([
  ['nodeRandom', nodeRandom],
  ['webCryptoRandom', webCryptoRandom],
] as const)('%s', (_name, random) => {
  it('bytes(16) returns a Uint8Array of length 16', () => {
    const b = random.bytes(16);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(b.length).toBe(16);
  });

  it('bytes(0) returns length 0', () => {
    const b = random.bytes(0);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(b.length).toBe(0);
  });

  it('two consecutive bytes(16) calls differ', () => {
    const a = random.bytes(16);
    const b = random.bytes(16);
    // Collision probability is 1/2^128 — negligible
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });

  it('uuid() matches RFC 4122 v4', () => {
    expect(random.uuid()).toMatch(UUID_V4_RE);
  });

  it('two consecutive uuid() calls differ', () => {
    const a = random.uuid();
    const b = random.uuid();
    expect(a).not.toBe(b);
  });
});
