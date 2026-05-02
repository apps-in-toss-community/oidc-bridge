import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_BYTES = 32;

export interface EncryptColumnInput {
  key: Buffer;
  plaintext: Buffer;
  aad: Buffer;
}

export interface DecryptColumnInput {
  key: Buffer;
  ciphertext: Buffer;
  aad: Buffer;
}

export function encryptColumn(input: EncryptColumnInput): Buffer {
  if (input.key.length !== KEY_BYTES) throw new Error('encryptColumn: key must be 32 bytes');
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', input.key, iv);
  cipher.setAAD(input.aad);
  const enc = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, enc, tag]);
}

export function decryptColumn(input: DecryptColumnInput): Buffer {
  if (input.key.length !== KEY_BYTES) throw new Error('decryptColumn: key must be 32 bytes');
  if (input.ciphertext.length < IV_BYTES + TAG_BYTES) {
    throw new Error('decryptColumn: ciphertext too short');
  }
  const iv = input.ciphertext.subarray(0, IV_BYTES);
  const tag = input.ciphertext.subarray(input.ciphertext.length - TAG_BYTES);
  const enc = input.ciphertext.subarray(IV_BYTES, input.ciphertext.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', input.key, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(input.aad);
  return Buffer.concat([decipher.update(enc), decipher.final()]);
}
