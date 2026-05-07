/**
 * Aead port — AES-256-GCM authenticated encryption.
 *
 * The interface keeps ciphertext and tag separate so callers can wire them into
 * the existing sealed-token wire format `[iv | ciphertext | tag]` (Task 9).
 * Both the WebCrypto impl (default, portable) and the Node impl
 * (`src/runtime/node-aead.ts`) produce byte-identical ciphertext + tag for the
 * same (key, iv, aad, plaintext) — cross-impl interop is verified by the
 * contract test in aead.test.ts.
 */

export interface AeadSealInput {
  /** 32 bytes (AES-256) */
  key: Uint8Array;
  /** 12 bytes (GCM nonce) */
  iv: Uint8Array;
  aad: Uint8Array;
  plaintext: Uint8Array;
}

export interface AeadOpenInput {
  key: Uint8Array;
  iv: Uint8Array;
  aad: Uint8Array;
  /** ciphertext WITHOUT the 16-byte tag */
  ciphertext: Uint8Array;
  /** 16 bytes — GCM authentication tag */
  tag: Uint8Array;
}

export interface Aead {
  seal(input: AeadSealInput): Promise<{ ciphertext: Uint8Array; tag: Uint8Array }>;
  open(input: AeadOpenInput): Promise<Uint8Array>;
}

// ---------------------------------------------------------------------------
// WebCrypto implementation (runtime-portable: works in Node 18+ and Workers)
// ---------------------------------------------------------------------------

const ALGO = 'AES-GCM';
const TAG_LENGTH_BITS = 128; // 16 bytes

// Copy a Uint8Array into a fresh ArrayBuffer so WebCrypto types are satisfied.
// `Uint8Array<ArrayBufferLike>` is not assignable to `BufferSource` (which
// requires `ArrayBuffer`, not `SharedArrayBuffer`).  Copying through
// `Buffer.from` — which is available in Node and confined to this file — gives
// us a plain `Uint8Array<ArrayBuffer>` that WebCrypto accepts.
function toPlainBuffer(u: Uint8Array): Uint8Array {
  // Buffer.from(u) copies into a new ArrayBuffer-backed Buffer (= Uint8Array).
  // We type it as `Uint8Array` (not `Buffer`) so the core layer stays portable.
  return new Uint8Array(u);
}

async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  // Ensure the backing buffer is a plain ArrayBuffer (not SharedArrayBuffer).
  const keyBuf = toPlainBuffer(raw);
  return crypto.subtle.importKey(
    'raw',
    keyBuf.buffer.slice(keyBuf.byteOffset, keyBuf.byteOffset + keyBuf.byteLength) as ArrayBuffer,
    { name: ALGO },
    false,
    ['encrypt', 'decrypt'],
  );
}

function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  const plain = toPlainBuffer(u);
  return plain.buffer.slice(plain.byteOffset, plain.byteOffset + plain.byteLength) as ArrayBuffer;
}

export const webCryptoAead: Aead = {
  async seal({ key, iv, aad, plaintext }) {
    const cryptoKey = await importKey(key);
    // WebCrypto returns ciphertext || tag (tag appended as last 16 bytes)
    const combined = await crypto.subtle.encrypt(
      {
        name: ALGO,
        iv: toArrayBuffer(iv),
        additionalData: toArrayBuffer(aad),
        tagLength: TAG_LENGTH_BITS,
      },
      cryptoKey,
      toArrayBuffer(plaintext),
    );
    const combined8 = new Uint8Array(combined);
    const tagOffset = combined8.length - 16;
    const ciphertext = combined8.slice(0, tagOffset);
    const tag = combined8.slice(tagOffset);
    return { ciphertext, tag };
  },

  async open({ key, iv, aad, ciphertext, tag }) {
    const cryptoKey = await importKey(key);
    // WebCrypto expects ciphertext || tag concatenated
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);
    let decrypted: ArrayBuffer;
    try {
      decrypted = await crypto.subtle.decrypt(
        {
          name: ALGO,
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(aad),
          tagLength: TAG_LENGTH_BITS,
        },
        cryptoKey,
        toArrayBuffer(combined),
      );
    } catch (err) {
      throw new Error(`AEAD_OPEN_FAILED: ${err instanceof Error ? err.message : String(err)}`);
    }
    return new Uint8Array(decrypted);
  },
};
