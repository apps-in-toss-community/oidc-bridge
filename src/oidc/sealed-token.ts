import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

export interface SealedPayload {
  appId: string;
  tossUserKey: string;
  tossAt: string;
  tossRt: string;
  tossAtExp: number;
  issuedAt: number;
}

export interface WrapInput {
  sealingKey: Buffer;
  sealingKeyVersion: number;
  payload: SealedPayload;
}

const VERSION_BYTES = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function wrapSealedToken(input: WrapInput): string {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const iv = randomBytes(IV_BYTES);
  const aad = buildAad(input.payload.appId, input.payload.tossUserKey, input.sealingKeyVersion);
  const cipher = createCipheriv('aes-256-gcm', input.sealingKey, iv);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(input.payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (tag.length !== TAG_BYTES) throw new Error('GCM tag length unexpected');
  const versionByte = Buffer.from([input.sealingKeyVersion]);
  const sealed = Buffer.concat([versionByte, iv, ciphertext, tag]);
  return `ait_${sealed.toString('base64url')}`;
}

export function buildAad(appId: string, tossUserKey: string, version: number): Buffer {
  return Buffer.from(`${appId} ${tossUserKey} ${version}`, 'utf8');
}

export interface UnwrapInput {
  token: string;
  resolveKey: (sealingKeyVersion: number) => Buffer;
  expectedAppId: string;
  expectedTossUserKey: string;
}

export function unwrapSealedToken(input: UnwrapInput): SealedPayload {
  if (!input.token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(input.token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  if (buf.length < VERSION_BYTES + IV_BYTES + TAG_BYTES + 1) {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  const version = buf[0]!;
  const iv = buf.subarray(VERSION_BYTES, VERSION_BYTES + IV_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(VERSION_BYTES + IV_BYTES, buf.length - TAG_BYTES);
  const key = input.resolveKey(version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(input.expectedAppId, input.expectedTossUserKey, version);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  const parsed = JSON.parse(plaintext.toString('utf8')) as SealedPayload;
  if (parsed.appId !== input.expectedAppId || parsed.tossUserKey !== input.expectedTossUserKey) {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}
