import { randomBytes, X509Certificate } from 'node:crypto';
import bcrypt from 'bcryptjs';

const CROCKFORD_B32 = '0123456789abcdefghjkmnpqrstvwxyz'; // RFC: i, l, o, u removed

/** `tnt_<24 Crockford-b32 chars>` from 15 random bytes (~120 bits entropy). */
export function generateTenantId(): string {
  const bytes = randomBytes(15);
  let bits = 0;
  let buffer = 0;
  let out = '';
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      const idx = (buffer >> bits) & 0x1f;
      out += CROCKFORD_B32[idx];
    }
  }
  return `tnt_${out}`;
}

/** 32 bytes → base64url (43 chars). */
export function generateClientSecret(): string {
  return randomBytes(32).toString('base64url');
}

export async function hashClientSecret(secret: string): Promise<string> {
  return bcrypt.hash(secret, 12);
}

export async function verifyClientSecret(
  secret: string,
  hashOrHashes: string | string[],
): Promise<boolean> {
  const hashes = Array.isArray(hashOrHashes) ? hashOrHashes : [hashOrHashes];
  for (const h of hashes) {
    if (await bcrypt.compare(secret, h)) return true;
  }
  return false;
}

export function certFingerprintSha256(pem: string): string {
  const cert = new X509Certificate(pem);
  // X509Certificate.fingerprint256 is "AB:CD:EF:..." uppercase. Normalize.
  return cert.fingerprint256.replaceAll(':', '').toLowerCase();
}

export function certNotAfterUnix(pem: string): number {
  const cert = new X509Certificate(pem);
  return Math.floor(new Date(cert.validTo).getTime() / 1000);
}
