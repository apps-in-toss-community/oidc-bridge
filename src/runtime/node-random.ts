import { randomBytes, randomUUID } from 'node:crypto';
import type { Random } from '../core/random.js';

export const nodeRandom: Random = {
  bytes(n) {
    const b = randomBytes(n);
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  },
  uuid() {
    return randomUUID();
  },
};
