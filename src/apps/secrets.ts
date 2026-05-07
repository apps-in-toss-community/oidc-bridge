import bcrypt from 'bcryptjs';
import { constantTimeEquals, fromHex, fromUtf8, toBase64Url, toHex } from '../core/bytes.js';
import type { Digest } from '../core/digest.js';
import type { Random } from '../core/random.js';
import { nodeDigest } from '../runtime/node-digest.js';
import { nodeRandom } from '../runtime/node-random.js';

const BCRYPT_ROUNDS = 12;

export function generateClientSecret(random: Random = nodeRandom): string {
  return toBase64Url(random.bytes(32));
}

export async function hashClientSecret(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_ROUNDS);
}

export async function verifyClientSecret(plain: string, hashes: string[]): Promise<boolean> {
  for (const h of hashes) {
    if (await bcrypt.compare(plain, h)) return true;
  }
  return false;
}

export function generateApiToken(random: Random = nodeRandom): string {
  return `tok_${toBase64Url(random.bytes(32))}`;
}

export async function hashApiToken(token: string, digest: Digest = nodeDigest): Promise<string> {
  const h = await digest.digest('SHA-256', fromUtf8(token));
  return toHex(h);
}

export async function verifyApiToken(
  plain: string,
  hash: string,
  digest: Digest = nodeDigest,
): Promise<boolean> {
  const computedHex = await hashApiToken(plain, digest);
  const computed = fromHex(computedHex);
  const expected = fromHex(hash);
  return constantTimeEquals(computed, expected);
}
