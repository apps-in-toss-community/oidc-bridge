import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 12;

function urlSafeRandom(byteLen: number): string {
  return randomBytes(byteLen).toString('base64url');
}

export function generateClientSecret(): string {
  return urlSafeRandom(32);
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

export function generateApiToken(): string {
  return `tok_${urlSafeRandom(32)}`;
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
