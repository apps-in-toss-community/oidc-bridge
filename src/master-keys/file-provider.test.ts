import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFileMasterKeyProvider } from './file-provider.js';

describe('createFileMasterKeyProvider', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-mkfile-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('returns key bytes for a version present', async () => {
    const bytes = Buffer.alloc(32, 0x55);
    writeFileSync(join(dir, 'v1.key'), bytes, { mode: 0o600 });
    const p = createFileMasterKeyProvider({ dir });
    const out = await p.getKeyBytes(1);
    expect(out.equals(bytes)).toBe(true);
  });

  it('lists discovered versions sorted', async () => {
    writeFileSync(join(dir, 'v3.key'), Buffer.alloc(32, 0x33), { mode: 0o600 });
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(32, 0x11), { mode: 0o600 });
    writeFileSync(join(dir, 'README.txt'), 'ignore me');
    const p = createFileMasterKeyProvider({ dir });
    expect(await p.listVersions()).toEqual([1, 3]);
  });

  it('throws when version is missing', async () => {
    const p = createFileMasterKeyProvider({ dir });
    await expect(p.getKeyBytes(99)).rejects.toThrow(/version 99/);
  });

  it('rejects key files shorter than 32 bytes', async () => {
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(16, 0x11), { mode: 0o600 });
    const p = createFileMasterKeyProvider({ dir });
    await expect(p.getKeyBytes(1)).rejects.toThrow(/at least 32 bytes/);
  });

  it('warns (does not throw) when key file is world-readable', async () => {
    const path = join(dir, 'v1.key');
    writeFileSync(path, Buffer.alloc(32, 0x11));
    chmodSync(path, 0o644);
    const warnings: string[] = [];
    const p = createFileMasterKeyProvider({
      dir,
      onWarning: (m) => warnings.push(m),
    });
    await p.getKeyBytes(1);
    expect(warnings.some((w) => /permissions/.test(w))).toBe(true);
  });
});
