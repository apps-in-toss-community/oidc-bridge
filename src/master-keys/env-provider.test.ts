import { afterEach, describe, expect, it } from 'vitest';
import { createEnvMasterKeyProvider } from './env-provider.js';

describe('createEnvMasterKeyProvider', () => {
  afterEach(() => {
    for (const k of Object.keys(process.env)) {
      if (k.startsWith('MASTER_KEY_TEST_')) delete process.env[k];
    }
  });

  it('returns key bytes for a version present in env', async () => {
    const hex = 'aa'.repeat(32);
    process.env.MASTER_KEY_TEST_1_HEX = hex;
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    const bytes = await p.getKeyBytes(1);
    expect(bytes).toHaveLength(32);
    expect(bytes.toString('hex')).toBe(hex);
  });

  it('lists discovered versions sorted', async () => {
    process.env.MASTER_KEY_TEST_2_HEX = 'bb'.repeat(32);
    process.env.MASTER_KEY_TEST_1_HEX = 'aa'.repeat(32);
    process.env.MASTER_KEY_TEST_5_HEX = 'cc'.repeat(32);
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    expect(await p.listVersions()).toEqual([1, 2, 5]);
  });

  it('throws when version is missing', async () => {
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    await expect(p.getKeyBytes(7)).rejects.toThrow(/version 7/);
  });

  it('rejects keys shorter than 32 bytes', async () => {
    process.env.MASTER_KEY_TEST_1_HEX = 'aa'.repeat(16);
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/at least 32 bytes/);
  });

  it('rejects non-hex content', async () => {
    process.env.MASTER_KEY_TEST_1_HEX = 'not-hex';
    const p = createEnvMasterKeyProvider({ prefix: 'MASTER_KEY_TEST_' });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/hex/);
  });
});
