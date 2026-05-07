/**
 * Node.js AES-256-GCM implementation of the Aead port.
 *
 * Uses `node:crypto` createCipheriv / createDecipheriv. Produces byte-identical
 * ciphertext + tag to the WebCrypto impl in `src/core/aead.ts` for the same
 * (key, iv, aad, plaintext) — this is the interop guarantee that lets Task 9
 * migrate `sealed-token.ts` to the Aead port without invalidating existing
 * `ait_*` tokens.
 *
 * `Buffer` is allowed inside this file (Node-only module). The port boundary
 * (`Aead` interface) always speaks `Uint8Array`.
 */

import { createCipheriv, createDecipheriv } from 'node:crypto';
import type { Aead } from '../core/aead.js';

export const nodeAead: Aead = {
  async seal({ key, iv, aad, plaintext }) {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const ct1 = cipher.update(plaintext);
    const ct2 = cipher.final();
    const ciphertext = new Uint8Array(ct1.length + ct2.length);
    ciphertext.set(ct1, 0);
    ciphertext.set(ct2, ct1.length);
    const tag = new Uint8Array(cipher.getAuthTag());
    return { ciphertext, tag };
  },

  async open({ key, iv, aad, ciphertext, tag }) {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    let pt1: Buffer;
    let pt2: Buffer;
    try {
      pt1 = decipher.update(Buffer.from(ciphertext));
      pt2 = decipher.final();
    } catch (err) {
      throw new Error(`AEAD_OPEN_FAILED: ${err instanceof Error ? err.message : String(err)}`);
    }
    const plaintext = new Uint8Array(pt1.length + pt2.length);
    plaintext.set(pt1, 0);
    plaintext.set(pt2, pt1.length);
    return plaintext;
  },
};
