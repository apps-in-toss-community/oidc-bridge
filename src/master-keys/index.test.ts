import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { toHex } from '../core/bytes.js';
import { createMasterKeyProvider } from './index.js';

describe('createMasterKeyProvider', () => {
  const origEnv = { ...process.env };
  let dir: string | null = null;

  beforeEach(() => {
    dir = null;
  });

  afterEach(() => {
    process.env = { ...origEnv };
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('builds an env-backed provider', async () => {
    process.env.MASTER_KEY_PROVIDER = 'env';
    process.env.MASTER_KEY_1_HEX = 'aa'.repeat(32);
    const p = createMasterKeyProvider();
    expect(await p.listVersions()).toEqual([1]);
    expect(toHex(await p.getKeyBytes(1))).toBe('aa'.repeat(32));
  });

  it('builds a file-backed provider', async () => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-mkfactory-'));
    process.env.MASTER_KEY_PROVIDER = 'file';
    process.env.MASTER_KEY_DIR = dir;
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(32, 0x42), { mode: 0o600 });
    const p = createMasterKeyProvider();
    expect(await p.listVersions()).toEqual([1]);
    expect((await p.getKeyBytes(1)).length).toBe(32);
  });

  it('throws on unknown provider', () => {
    process.env.MASTER_KEY_PROVIDER = 'wat';
    expect(() => createMasterKeyProvider()).toThrow(/MASTER_KEY_PROVIDER/);
  });

  it('defaults to env provider when MASTER_KEY_PROVIDER is unset', async () => {
    delete process.env.MASTER_KEY_PROVIDER;
    process.env.MASTER_KEY_1_HEX = 'cc'.repeat(32);
    const p = createMasterKeyProvider();
    expect(await p.listVersions()).toEqual([1]);
  });

  it('rejects file provider without MASTER_KEY_DIR', () => {
    process.env.MASTER_KEY_PROVIDER = 'file';
    delete process.env.MASTER_KEY_DIR;
    expect(() => createMasterKeyProvider()).toThrow(/MASTER_KEY_DIR/);
  });
});
