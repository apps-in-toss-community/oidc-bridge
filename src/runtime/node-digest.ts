import { createHash } from 'node:crypto';
import type { Digest } from '../core/digest.js';

export const nodeDigest: Digest = {
  async digest(_algo, input) {
    // map 'SHA-256' → 'sha256' for node
    const out = createHash('sha256').update(input).digest();
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  },
};
