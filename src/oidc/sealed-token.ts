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
const APPID_LEN_BYTES = 1;
const USERKEY_LEN_BYTES = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function wrapSealedToken(input: WrapInput): string {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const appIdBuf = Buffer.from(input.payload.appId, 'utf8');
  if (appIdBuf.length === 0 || appIdBuf.length > 255) {
    throw new Error('appId length out of range');
  }
  const userKeyBuf = Buffer.from(input.payload.tossUserKey, 'utf8');
  if (userKeyBuf.length === 0 || userKeyBuf.length > 255) {
    throw new Error('tossUserKey length out of range');
  }
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
    Buffer.from([appIdBuf.length]),
    appIdBuf,
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
  const parts = parseSealed(input.token);
  if (parts.appId !== input.expectedAppId) throw new Error('SEALED_TOKEN_TAMPERED');
  return decryptOrThrow(parts, input.resolveKey, input.expectedAppId);
}

export function peekSealedTokenVersion(token: string): number {
  return parseSealed(token).version;
}

export function peekSealedTokenAppId(token: string): string {
  return parseSealed(token).appId;
}

export function peekSealedTokenUserKey(token: string): string {
  return parseSealed(token).userKey;
}

interface ParsedSealed {
  version: number;
  appId: string;
  userKey: string;
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

function parseSealed(token: string): ParsedSealed {
  if (!token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Buffer;
  try {
    buf = Buffer.from(token.slice(4), 'base64url');
  } catch {
    throw new Error('SEALED_TOKEN_BAD_FORMAT');
  }
  let off = 0;
  if (buf.length < off + VERSION_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const version = buf[off]!;
  off += VERSION_BYTES;
  if (buf.length < off + APPID_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const appIdLen = buf[off]!;
  off += APPID_LEN_BYTES;
  if (buf.length < off + appIdLen) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const appId = buf.subarray(off, off + appIdLen).toString('utf8');
  off += appIdLen;
  if (buf.length < off + USERKEY_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKeyLen = buf[off]!;
  off += USERKEY_LEN_BYTES;
  if (buf.length < off + userKeyLen) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKey = buf.subarray(off, off + userKeyLen).toString('utf8');
  off += userKeyLen;
  if (buf.length < off + IV_BYTES + TAG_BYTES + 1) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const iv = buf.subarray(off, off + IV_BYTES);
  off += IV_BYTES;
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(off, buf.length - TAG_BYTES);
  return { version, appId, userKey, iv, ciphertext, tag };
}

function decryptOrThrow(
  parts: ParsedSealed,
  resolveKey: (v: number) => Buffer,
  expectedAppId: string,
): SealedPayload {
  const key = resolveKey(parts.version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(expectedAppId, parts.userKey, parts.version);
  const decipher = createDecipheriv('aes-256-gcm', key, parts.iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(parts.tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(parts.ciphertext), decipher.final()]);
  } catch {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  const parsed = JSON.parse(plaintext.toString('utf8')) as SealedPayload;
  if (parsed.appId !== expectedAppId || parsed.tossUserKey !== parts.userKey) {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}

export function buildAad(appId: string, tossUserKey: string, version: number): Buffer {
  return Buffer.from(`${appId} ${tossUserKey} ${version}`, 'utf8');
}
