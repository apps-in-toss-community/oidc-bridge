/**
 * Node.js HKDF-SHA-256 implementation of the Kdf port.
 *
 * Uses `node:crypto` hkdfSync. Produces byte-identical output to the
 * WebCrypto impl in `src/core/kdf.ts` for the same inputs — this is the
 * interop guarantee that lets sealed `ait_*` tokens keep decrypting across
 * runtime changes.
 *
 * `Buffer` is allowed inside this file (Node-only module). The port boundary
 * (`Kdf` interface) always speaks `Uint8Array`.
 */

import { hkdfSync } from 'node:crypto';
import type { Kdf } from '../core/kdf.js';

export const nodeKdf: Kdf = {
  async deriveBits({ secret, salt, info, hash, lengthBytes }) {
    // hkdfSync takes hash as a lowercase Node digest name ('sha256').
    const nodeHash = hash.toLowerCase().replace('-', '') as 'sha256';
    // hkdfSync returns an ArrayBuffer; wrap without copy for zero-overhead.
    const buf = hkdfSync(nodeHash, secret, salt, info, lengthBytes);
    return new Uint8Array(buf);
  },
};
