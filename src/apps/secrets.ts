import { createHash, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { toBase64Url } from '../core/bytes.js';
import type { Random } from '../core/random.js';
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

export function hashApiToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function verifyApiToken(plain: string, hash: string): boolean {
  const computed = Buffer.from(hashApiToken(plain), 'hex');
  const expected = Buffer.from(hash, 'hex');
  if (computed.length !== expected.length) return false;
  return timingSafeEqual(computed, expected);
}
