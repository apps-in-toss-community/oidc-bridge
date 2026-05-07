import { describe, expect, it } from 'vitest';
import { createWorkersMasterKeyProvider } from './workers-master-key-provider.js';

const VALID_HEX_32 = 'aa'.repeat(32);
const VALID_HEX_32_B = 'bb'.repeat(32);

describe('createWorkersMasterKeyProvider', () => {
  it('reads MASTER_KEY_V1_HEX from env and returns a 32-byte Uint8Array', async () => {
    const p = createWorkersMasterKeyProvider({
      env: { MASTER_KEY_V1_HEX: VALID_HEX_32 },
    });
    const bytes = await p.getKeyBytes(1);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(32);
    expect(Array.from(bytes)).toEqual(Array.from({ length: 32 }, () => 0xaa));
  });

  it('throws when version is missing', async () => {
    const p = createWorkersMasterKeyProvider({ env: {} });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/version 1/);
  });

  it('throws when value is not a string (non-string binding)', async () => {
    const p = createWorkersMasterKeyProvider({
      env: { MASTER_KEY_V1_HEX: 42 },
    });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/version 1/);
  });

  it('throws when value is not valid hex', async () => {
    const p = createWorkersMasterKeyProvider({
      env: { MASTER_KEY_V1_HEX: 'not-hex!!'.repeat(4) },
    });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/hex/);
  });

  it('throws when key is too short (< 32 bytes)', async () => {
    const p = createWorkersMasterKeyProvider({
      env: { MASTER_KEY_V1_HEX: 'aa'.repeat(16) },
    });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/at least 32 bytes/);
  });

  it('listVersions discovers all MASTER_KEY_V<n>_HEX keys sorted ascending', async () => {
    const p = createWorkersMasterKeyProvider({
      env: {
        MASTER_KEY_V2_HEX: VALID_HEX_32_B,
        MASTER_KEY_V1_HEX: VALID_HEX_32,
        UNRELATED_KEY: 'ignored',
        MASTER_KEY_V5_HEX: VALID_HEX_32,
      },
    });
    expect(await p.listVersions()).toEqual([1, 2, 5]);
  });

  it('returns empty array from listVersions when no matching keys exist', async () => {
    const p = createWorkersMasterKeyProvider({ env: { UNRELATED: 'x' } });
    expect(await p.listVersions()).toEqual([]);
  });

  it('honors a custom prefix', async () => {
    const p = createWorkersMasterKeyProvider({
      env: {
        MY_PREFIX_1_HEX: VALID_HEX_32,
        MASTER_KEY_V1_HEX: VALID_HEX_32_B, // default prefix key, should be ignored
      },
      prefix: 'MY_PREFIX_',
    });
    const versions = await p.listVersions();
    expect(versions).toEqual([1]);
    const bytes = await p.getKeyBytes(1);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(32);
    expect(Array.from(bytes)).toEqual(Array.from({ length: 32 }, () => 0xaa));
  });

  it('result is a plain Uint8Array, not specifically a Buffer', async () => {
    const p = createWorkersMasterKeyProvider({
      env: { MASTER_KEY_V1_HEX: VALID_HEX_32 },
    });
    const bytes = await p.getKeyBytes(1);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(Buffer.isBuffer(bytes)).toBe(false);
  });
});
