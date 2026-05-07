/**
 * Kdf port — HKDF-SHA-256 key derivation.
 *
 * Both the WebCrypto impl (runtime-portable: Node 18+ and Workers) and the
 * Node impl (`src/runtime/node-kdf.ts`) produce byte-identical output for the
 * same inputs — cross-impl byte equality is verified in kdf.test.ts and is the
 * contract that allows sealed `ait_*` tokens issued before this PR to keep
 * decrypting after Task 9.
 */

export interface KdfDeriveInput {
  /** Input keying material (≥32 bytes for our usage; the port does not enforce). */
  secret: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array;
  /** Only SHA-256 is needed today; keep the type narrow. */
  hash: 'SHA-256';
  /** Desired output length in bytes. */
  lengthBytes: number;
}

export interface Kdf {
  deriveBits(input: KdfDeriveInput): Promise<Uint8Array>;
}

// ---------------------------------------------------------------------------
// WebCrypto implementation (runtime-portable: works in Node 18+ and Workers)
// ---------------------------------------------------------------------------

// Copy a Uint8Array into a plain ArrayBuffer-backed buffer so WebCrypto types
// are satisfied. `Uint8Array<ArrayBufferLike>` is not assignable to
// `BufferSource` (which requires `ArrayBuffer`, not `SharedArrayBuffer`).
function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  const plain = new Uint8Array(u);
  return plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength) as ArrayBuffer;
}

export const webCryptoKdf: Kdf = {
  async deriveBits({ secret, salt, info, hash, lengthBytes }) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(secret),
      { name: 'HKDF' },
      false,
      ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash,
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(info),
      },
      baseKey,
      // WebCrypto takes BITS; the port interface uses BYTES.
      lengthBytes * 8,
    );
    return new Uint8Array(bits);
  },
};
