import { fromUtf8 } from '../core/bytes.js';
import type { Kdf } from '../core/kdf.js';
import { nodeKdf } from '../runtime/node-kdf.js';

export interface DeriveSealingKeyInput {
  /** Input keying material. Was Buffer; widened to Uint8Array (Buffer is still assignable). */
  masterKey: Uint8Array;
  appId: string;
  /** KDF implementation — defaults to nodeKdf (injected for cross-impl testing). */
  kdf?: Kdf;
}

const SEALING_KEY_BYTES = 32;
const HKDF_INFO = 'ait/seal/v1';

export async function deriveSealingKey(input: DeriveSealingKeyInput): Promise<Uint8Array> {
  if (!input.appId || input.appId.length === 0) {
    throw new Error('deriveSealingKey: appId required');
  }
  if (input.masterKey.length < 32) {
    throw new Error('deriveSealingKey: master key must be at least 32 bytes');
  }
  const kdf = input.kdf ?? nodeKdf;
  return kdf.deriveBits({
    secret: input.masterKey,
    salt: fromUtf8(input.appId),
    info: fromUtf8(HKDF_INFO),
    hash: 'SHA-256',
    lengthBytes: SEALING_KEY_BYTES,
  });
}
