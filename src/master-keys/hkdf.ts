import { hkdfSync } from 'node:crypto';

export interface DeriveSealingKeyInput {
  masterKey: Buffer;
  appId: string;
}

const SEALING_KEY_BYTES = 32;
const HKDF_INFO = 'ait/seal/v1';
const HKDF_HASH = 'sha256';

export function deriveSealingKey(input: DeriveSealingKeyInput): Buffer {
  if (!input.appId || input.appId.length === 0) {
    throw new Error('deriveSealingKey: appId required');
  }
  if (input.masterKey.length < 32) {
    throw new Error('deriveSealingKey: master key must be at least 32 bytes');
  }
  const salt = Buffer.from(input.appId, 'utf8');
  const info = Buffer.from(HKDF_INFO, 'utf8');
  const derived = hkdfSync(HKDF_HASH, input.masterKey, salt, info, SEALING_KEY_BYTES);
  return Buffer.from(derived);
}
