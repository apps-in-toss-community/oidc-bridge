import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import bcrypt from 'bcryptjs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSqliteStorage } from '../../src/storage/sqlite.js';
import { setUserPasswordOffline } from './user.js';

describe('setUserPasswordOffline', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-cli-user-'));
    dbPath = join(dir, 'test.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('writes a bcrypt hash for an existing user', async () => {
    const seed = createSqliteStorage({ path: dbPath });
    await seed.createUser({ id: 'user_1', email: 'a@x.com' });
    await seed.close();

    await setUserPasswordOffline({ dbPath, email: 'a@x.com', password: 'hunter2' });

    const verify = createSqliteStorage({ path: dbPath });
    const u = await verify.getUserByEmail('a@x.com');
    await verify.close();
    expect(u?.passwordHash).toMatch(/^\$2[aby]\$12\$/);
    if (!u?.passwordHash) throw new Error('no hash written');
    expect(await bcrypt.compare('hunter2', u.passwordHash)).toBe(true);
  });

  it('throws when the email is unknown', async () => {
    const seed = createSqliteStorage({ path: dbPath });
    await seed.close();
    await expect(
      setUserPasswordOffline({ dbPath, email: 'missing@x.com', password: 'pw' }),
    ).rejects.toThrow(/missing@x\.com/);
  });

  it('rejects empty password', async () => {
    await expect(
      setUserPasswordOffline({ dbPath, email: 'a@x.com', password: '' }),
    ).rejects.toThrow(/password/i);
  });
});
