import { describe, expect, it } from 'vitest';
import { decryptColumn, encryptColumn } from './encryption.js';

describe('column encryption', () => {
  const key = Buffer.alloc(32, 0x42);
  const plaintext = Buffer.from(
    '-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBg...\n-----END PRIVATE KEY-----',
  );
  const aad = Buffer.from('app_xyz', 'utf8');

  it('roundtrips encrypt → decrypt', () => {
    const enc = encryptColumn({ key, plaintext, aad });
    const out = decryptColumn({ key, ciphertext: enc, aad });
    expect(out.equals(plaintext)).toBe(true);
  });

  it('fails when AAD differs', () => {
    const enc = encryptColumn({ key, plaintext, aad });
    expect(() => decryptColumn({ key, ciphertext: enc, aad: Buffer.from('different') })).toThrow();
  });

  it('fails when key differs', () => {
    const enc = encryptColumn({ key, plaintext, aad });
    expect(() => decryptColumn({ key: Buffer.alloc(32, 0xff), ciphertext: enc, aad })).toThrow();
  });

  it('produces different ciphertexts for the same input (random IV)', () => {
    const a = encryptColumn({ key, plaintext, aad });
    const b = encryptColumn({ key, plaintext, aad });
    expect(a.equals(b)).toBe(false);
  });

  it('rejects keys not 32 bytes', () => {
    expect(() => encryptColumn({ key: Buffer.alloc(16), plaintext, aad })).toThrow(/32 bytes/);
  });
});
