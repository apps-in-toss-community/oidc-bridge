import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runDbProbe } from './db-probe.js';

describe('runDbProbe (sqlite)', () => {
  it('green on a fully-migrated DB (file exists, second open)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-db-probe-'));
    const dbPath = join(dir, 'bridge.db');
    // First open creates the file.
    await runDbProbe({ storage: 'sqlite', sqlitePath: dbPath });
    expect(existsSync(dbPath)).toBe(true);
    // Second open finds it pre-existing → green.
    const r = await runDbProbe({ storage: 'sqlite', sqlitePath: dbPath });
    expect(r.state).toBe('green');
    expect(r.detail).toContain('sqlite');
  });

  it('yellow when migrations had to apply this run (DB file did not exist)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-db-probe-'));
    const dbPath = join(dir, 'fresh.db');
    const r = await runDbProbe({ storage: 'sqlite', sqlitePath: dbPath });
    expect(r.state).toBe('yellow');
    expect(r.detail).toMatch(/created|migrations/);
  });

  it('red when sqlitePath is unwritable', async () => {
    // /no-such-dir/that/cant/exist is unwritable.
    const r = await runDbProbe({
      storage: 'sqlite',
      sqlitePath: '/no-such-dir-doctor-probe/sub/bridge.db',
    });
    expect(r.state).toBe('red');
  });

  it('red when sqlite file is corrupt', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-db-probe-'));
    const dbPath = join(dir, 'corrupt.db');
    writeFileSync(dbPath, Buffer.from('not a sqlite file'));
    const r = await runDbProbe({ storage: 'sqlite', sqlitePath: dbPath });
    expect(r.state).toBe('red');
  });

  it('red when storage=pg and connectionString is invalid', async () => {
    const r = await runDbProbe({ storage: 'pg', connectionString: 'postgres://0.0.0.0:1/bogus' });
    expect(r.state).toBe('red');
  });
});
