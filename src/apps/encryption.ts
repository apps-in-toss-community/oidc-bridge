import { type Aead, aead as defaultAead } from '../core/aead.js';
import { concat } from '../core/bytes.js';
import type { Random } from '../core/random.js';
import { nodeRandom } from '../runtime/node-random.js';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export interface EncryptColumnInput {
  key: Uint8Array;
  plaintext: Uint8Array;
  aad: Uint8Array;
  random?: Random;
  aead?: Aead;
}

export interface DecryptColumnInput {
  key: Uint8Array;
  ciphertext: Uint8Array;
  aad: Uint8Array;
  aead?: Aead;
}

export async function encryptColumn(input: EncryptColumnInput): Promise<Uint8Array> {
  if (input.key.length !== KEY_BYTES) throw new Error('encryptColumn: key must be 32 bytes');
  const random = input.random ?? nodeRandom;
  const aeadImpl = input.aead ?? defaultAead;
  const iv = random.bytes(IV_BYTES);
  const { ciphertext, tag } = await aeadImpl.seal({
    key: input.key,
    iv,
    aad: input.aad,
    plaintext: input.plaintext,
  });
  return concat(iv, ciphertext, tag);
}

export async function decryptColumn(input: DecryptColumnInput): Promise<Uint8Array> {
  if (input.key.length !== KEY_BYTES) throw new Error('decryptColumn: key must be 32 bytes');
  if (input.ciphertext.length < IV_BYTES + TAG_BYTES) {
    throw new Error('decryptColumn: ciphertext too short');
  }
  const iv = input.ciphertext.subarray(0, IV_BYTES);
  const tag = input.ciphertext.subarray(input.ciphertext.length - TAG_BYTES);
  const enc = input.ciphertext.subarray(IV_BYTES, input.ciphertext.length - TAG_BYTES);
  const aeadImpl = input.aead ?? defaultAead;
  return aeadImpl.open({ key: input.key, iv, aad: input.aad, ciphertext: enc, tag });
}
