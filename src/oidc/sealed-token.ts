import { type Aead, aead as defaultAead } from '../core/aead.js';
import { concat, fromBase64Url, fromUtf8, toBase64Url, toUtf8 } from '../core/bytes.js';
import type { Random } from '../core/random.js';
import { nodeRandom } from '../runtime/node-random.js';

export interface SealedPayload {
  appId: string;
  tossUserKey: string;
  tossAt: string;
  tossRt: string;
  tossAtExp: number;
  issuedAt: number;
}

export interface WrapInput {
  sealingKey: Uint8Array;
  sealingKeyVersion: number;
  payload: SealedPayload;
  random?: Random;
  aead?: Aead;
}

const VERSION_BYTES = 1;
const APPID_LEN_BYTES = 1;
const USERKEY_LEN_BYTES = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export async function wrapSealedToken(input: WrapInput): Promise<string> {
  if (input.sealingKey.length !== 32) throw new Error('sealingKey must be 32 bytes');
  if (input.sealingKeyVersion < 1 || input.sealingKeyVersion > 255) {
    throw new Error('sealingKeyVersion must fit in 1 byte');
  }
  const appIdBytes = fromUtf8(input.payload.appId);
  if (appIdBytes.length === 0 || appIdBytes.length > 255) {
    throw new Error('appId length out of range');
  }
  const userKeyBytes = fromUtf8(input.payload.tossUserKey);
  if (userKeyBytes.length === 0 || userKeyBytes.length > 255) {
    throw new Error('tossUserKey length out of range');
  }
  const random = input.random ?? nodeRandom;
  const aeadImpl = input.aead ?? defaultAead;
  const iv = random.bytes(IV_BYTES);
  const aad = buildAad(input.payload.appId, input.payload.tossUserKey, input.sealingKeyVersion);
  const plaintext = fromUtf8(JSON.stringify(input.payload));
  const { ciphertext, tag } = await aeadImpl.seal({
    key: input.sealingKey,
    iv,
    aad,
    plaintext,
  });
  if (tag.length !== TAG_BYTES) throw new Error('GCM tag length unexpected');
  const sealed = concat(
    new Uint8Array([input.sealingKeyVersion]),
    new Uint8Array([appIdBytes.length]),
    appIdBytes,
    new Uint8Array([userKeyBytes.length]),
    userKeyBytes,
    iv,
    ciphertext,
    tag,
  );
  return `ait_${toBase64Url(sealed)}`;
}

export interface UnwrapInput {
  token: string;
  resolveKey: (sealingKeyVersion: number) => Uint8Array;
  expectedAppId: string;
  aead?: Aead;
}

export async function unwrapSealedToken(input: UnwrapInput): Promise<SealedPayload> {
  const parts = parseSealed(input.token);
  if (parts.appId !== input.expectedAppId) throw new Error('SEALED_TOKEN_TAMPERED');
  return decryptOrThrow(parts, input.resolveKey, input.expectedAppId, input.aead ?? defaultAead);
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
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

function parseSealed(token: string): ParsedSealed {
  if (!token.startsWith('ait_')) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  let buf: Uint8Array;
  try {
    buf = fromBase64Url(token.slice(4));
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
  const appId = toUtf8(buf.subarray(off, off + appIdLen));
  off += appIdLen;
  if (buf.length < off + USERKEY_LEN_BYTES) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKeyLen = buf[off]!;
  off += USERKEY_LEN_BYTES;
  if (buf.length < off + userKeyLen) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const userKey = toUtf8(buf.subarray(off, off + userKeyLen));
  off += userKeyLen;
  if (buf.length < off + IV_BYTES + TAG_BYTES + 1) throw new Error('SEALED_TOKEN_BAD_FORMAT');
  const iv = buf.subarray(off, off + IV_BYTES);
  off += IV_BYTES;
  const tag = buf.subarray(buf.length - TAG_BYTES);
  const ciphertext = buf.subarray(off, buf.length - TAG_BYTES);
  return { version, appId, userKey, iv, ciphertext, tag };
}

async function decryptOrThrow(
  parts: ParsedSealed,
  resolveKey: (v: number) => Uint8Array,
  expectedAppId: string,
  aeadImpl: Aead,
): Promise<SealedPayload> {
  const key = resolveKey(parts.version);
  if (key.length !== 32) throw new Error('SEALED_TOKEN_BAD_KEY');
  const aad = buildAad(expectedAppId, parts.userKey, parts.version);
  let plaintext: Uint8Array;
  try {
    plaintext = await aeadImpl.open({
      key,
      iv: parts.iv,
      aad,
      ciphertext: parts.ciphertext,
      tag: parts.tag,
    });
  } catch {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  const parsed = JSON.parse(toUtf8(plaintext)) as SealedPayload;
  if (parsed.appId !== expectedAppId || parsed.tossUserKey !== parts.userKey) {
    throw new Error('SEALED_TOKEN_TAMPERED');
  }
  return parsed;
}

export function buildAad(appId: string, tossUserKey: string, version: number): Uint8Array {
  return fromUtf8(`${appId} ${tossUserKey} ${version}`);
}
