import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import bcrypt from 'bcryptjs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createSqliteStorage } from '../../src/storage/sqlite.js';
import { createUserOffline, setUserPasswordOffline } from './user.js';

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

describe('createUserOffline', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-cli-create-user-'));
    dbPath = join(dir, 'test.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('happy: creates a user, returns it, getUserByEmail returns the row', async () => {
    const u = await createUserOffline({ dbPath, email: 'new@x.com', id: 'explicit_id' });
    expect(u.id).toBe('explicit_id');
    expect(u.email).toBe('new@x.com');

    const verify = createSqliteStorage({ path: dbPath });
    const row = await verify.getUserByEmail('new@x.com');
    await verify.close();
    expect(row?.id).toBe('explicit_id');
    expect(row?.email).toBe('new@x.com');
  });

  it('auto-id: when id omitted, returns a 32-hex string id', async () => {
    const u = await createUserOffline({ dbPath, email: 'auto@x.com' });
    expect(u.id).toMatch(/^[0-9a-f]{32}$/);
  });

  it('explicit id: when id provided, that id is used', async () => {
    const u = await createUserOffline({ dbPath, email: 'ex@x.com', id: 'my_custom_id' });
    expect(u.id).toBe('my_custom_id');
  });

  it('conflict: creating a second user with the same email throws /already exists/', async () => {
    await createUserOffline({ dbPath, email: 'dup@x.com' });
    await expect(createUserOffline({ dbPath, email: 'dup@x.com' })).rejects.toThrow(
      /already exists/,
    );
  });
});
