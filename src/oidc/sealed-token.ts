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
const USERKEY_LEN_BYTES = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function wrapSealedToken(input: WrapInput): string {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const userKeyBuf = Buffer.from(input.payload.tossUserKey, 'utf8');
  if (userKeyBuf.length > 255) throw new Error('tossUserKey too long');
  const iv = randomBytes(IV_BYTES);
  const aad = buildAad(input.payload.appId, input.payload.tossUserKey, input.sealingKeyVersion);
  const cipher = createCipheriv('aes-256-gcm', input.sealingKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(input.payload), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  if (tag.length !== TAG_BYTES) throw new Error('GCM tag length unexpected');
  const sealed = Buffer.concat([
    Buffer.from([input.sealingKeyVersion]),
    Buffer.from([userKeyBuf.length]),
    userKeyBuf,
    iv,
    ciphertext,
    tag,
  ]);
  return `ait_${sealed.toString('base64url')}`;
}

export interface UnwrapInput {
  token: string;
  resolveKey: (sealingKeyVersion: number) => Buffer;
  expectedAppId: string;
}

export function unwrapSealedToken(input: UnwrapInput): SealedPayload {
  const { version, userKey, iv, ciphertext, tag } = parseSealed(input.token);
  const key = input.resolveKey(version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(input.expectedAppId, userKey, version);
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
  if (parsed.appId !== input.expectedAppId || parsed.tossUserKey !== userKey) {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}

export function peekSealedTokenVersion(token: string): number {
  return parseSealed(token).version;
}

export function peekSealedTokenUserKey(token: string): string {
  return parseSealed(token).userKey;
}

function parseSealed(token: string) {
  if (!token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  if (buf.length < VERSION_BYTES + USERKEY_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const version = buf[0]!;
  const userKeyLen = buf[1]!;
  const userKeyEnd = VERSION_BYTES + USERKEY_LEN_BYTES + userKeyLen;
  if (buf.length < userKeyEnd + IV_BYTES + TAG_BYTES + 1)
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKey = buf.subarray(VERSION_BYTES + USERKEY_LEN_BYTES, userKeyEnd).toString('utf8');
  const iv = buf.subarray(userKeyEnd, userKeyEnd + IV_BYTES);
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(userKeyEnd + IV_BYTES, buf.length - TAG_BYTES);
  return { version, userKey, iv, ciphertext, tag };
}

export function buildAad(appId: string, tossUserKey: string, version: number): Buffer {
  return Buffer.from(`${appId} ${tossUserKey} ${version}`, 'utf8');
}
