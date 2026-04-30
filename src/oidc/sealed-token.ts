import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

export interface SealedPayload {
  tenant_id: string;
  toss_access_token: string;
  toss_refresh_token: string;
  exp: number;
}

const TOKEN_PREFIX = 'aitc_';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const VERSION_BYTE = 0x01;

export function deriveSealingKey(
  masterKey: Buffer,
  tenantId: string,
  sealingKeyVersion: number,
): Buffer {
  const info = `oidc-bridge sealing v${sealingKeyVersion}`;
  return Buffer.from(
    hkdfSync('sha256', masterKey, Buffer.from(tenantId, 'utf8'), Buffer.from(info, 'utf8'), 32),
  );
}

function buildHeader(sealingKeyVersion: number, tenantId: string): Buffer {
  const idBytes = Buffer.from(tenantId, 'utf8');
  if (idBytes.length > 0xff) throw new Error('tenant_id too long');
  return Buffer.concat([Buffer.from([VERSION_BYTE, sealingKeyVersion, idBytes.length]), idBytes]);
}

export function sealAccessToken(args: {
  payload: SealedPayload;
  masterKey: Buffer;
  sealingKeyVersion: number;
}): string {
  const header = buildHeader(args.sealingKeyVersion, args.payload.tenant_id);
  const key = deriveSealingKey(args.masterKey, args.payload.tenant_id, args.sealingKeyVersion);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(header);
  const ct = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(args.payload), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return TOKEN_PREFIX + Buffer.concat([header, nonce, tag, ct]).toString('base64url');
}

export function unsealAccessToken(args: {
  token: string;
  masterKey: Buffer;
  sealingKeyVersionOf: (tenantId: string) => number;
}): SealedPayload {
  if (!args.token.startsWith(TOKEN_PREFIX)) throw new Error('sealed token format');
  const wire = Buffer.from(args.token.slice(TOKEN_PREFIX.length), 'base64url');
  if (wire.length < 3 + NONCE_BYTES + TAG_BYTES) throw new Error('sealed token truncated');
  if (wire[0] !== VERSION_BYTE) throw new Error(`sealed token wire version ${wire[0]}`);
  const sealingKeyVersion = wire[1] as number;
  const idLen = wire[2] as number;
  const headerLen = 3 + idLen;
  if (wire.length < headerLen + NONCE_BYTES + TAG_BYTES) throw new Error('sealed token truncated');
  const tenantId = wire.subarray(3, headerLen).toString('utf8');
  const expectedVersion = args.sealingKeyVersionOf(tenantId);
  if (expectedVersion !== sealingKeyVersion) {
    throw new Error('sealing key version mismatch (auth)');
  }
  const header = wire.subarray(0, headerLen);
  const nonce = wire.subarray(headerLen, headerLen + NONCE_BYTES);
  const tag = wire.subarray(headerLen + NONCE_BYTES, headerLen + NONCE_BYTES + TAG_BYTES);
  const ct = wire.subarray(headerLen + NONCE_BYTES + TAG_BYTES);
  const key = deriveSealingKey(args.masterKey, tenantId, sealingKeyVersion);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch (_err) {
    throw new Error('sealed token failed authentication tag (tamper)');
  }
  return JSON.parse(plaintext.toString('utf8')) as SealedPayload;
}
