import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runMasterKeyProbe } from './master-key-probe.js';

describe('runMasterKeyProbe', () => {
  it('green for a valid file provider with 32-byte v1 key', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    const path = join(dir, 'v1.key');
    writeFileSync(path, Buffer.alloc(32, 0x42));
    chmodSync(path, 0o600);
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    expect(r.state).toBe('green');
  });

  it('red when key file is shorter than 32 bytes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(16, 0));
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    expect(r.state).toBe('red');
  });

  it('red when key file is missing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('not present');
  });

  it('red when MASTER_KEY_PROVIDER=file but masterKeyDir is missing', async () => {
    const r = await runMasterKeyProbe({ provider: 'file', version: 1 });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('MASTER_KEY_DIR');
  });

  it('green for env provider when MASTER_KEY_<V>_HEX is set', async () => {
    const env: Record<string, string | undefined> = {
      MASTER_KEY_PROVIDER: 'env',
      MASTER_KEY_1_HEX: '00'.repeat(32),
    };
    const r = await runMasterKeyProbe({ provider: 'env', version: 1, env });
    expect(r.state).toBe('green');
  });

  it('red when env provider hex is missing', async () => {
    const env: Record<string, string | undefined> = { MASTER_KEY_PROVIDER: 'env' };
    const r = await runMasterKeyProbe({ provider: 'env', version: 1, env });
    expect(r.state).toBe('red');
  });

  it('yellow when file mode is too open (still readable)', async () => {
    if (process.platform === 'win32') return; // POSIX-only check.
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    const path = join(dir, 'v1.key');
    writeFileSync(path, Buffer.alloc(32, 0x42));
    chmodSync(path, 0o644);
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    // File still loads; provider warns about mode. Probe surfaces the warning.
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('chmod 600');
  });
});
