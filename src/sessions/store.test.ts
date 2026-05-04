import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { createSqliteStorage } from '../storage/sqlite.js';
import { createSessionStore } from './store.js';

describe('SessionStore (sqlite)', () => {
  let dir: string;
  let storage: Storage;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-sessions-'));
    storage = createSqliteStorage({ path: join(dir, 'test.db') });
    await storage.createUser({ id: 'u_1', email: 'a@b' });
  });

  afterEach(async () => {
    await storage.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('create then get returns the row with a 32-hex id', async () => {
    const store = createSessionStore(storage);
    const created = await store.create('u_1', 60_000);
    expect(created.id).toMatch(/^[0-9a-f]{32}$/);
    const fetched = await store.get(created.id);
    expect(fetched?.userId).toBe('u_1');
    expect(fetched?.expiresAt).toBeInstanceOf(Date);
  });

  it('get returns null for unknown id', async () => {
    const store = createSessionStore(storage);
    expect(await store.get('deadbeefdeadbeefdeadbeefdeadbeef')).toBeNull();
  });

  it('get returns null for expired sessions even before purge', async () => {
    const store = createSessionStore(storage);
    await storage.createUserSession({
      id: 'expired1',
      userId: 'u_1',
      expiresAt: new Date(Date.now() - 1_000),
    });
    expect(await store.get('expired1')).toBeNull();
  });

  it('revoke removes the row', async () => {
    const store = createSessionStore(storage);
    const s = await store.create('u_1', 60_000);
    await store.revoke(s.id);
    expect(await store.get(s.id)).toBeNull();
  });

  it('revokeForUser removes all sessions for user', async () => {
    const store = createSessionStore(storage);
    const a = await store.create('u_1', 60_000);
    const b = await store.create('u_1', 60_000);
    await storage.createUser({ id: 'u_2', email: 'c@d' });
    const c = await store.create('u_2', 60_000);
    await store.revokeForUser('u_1');
    expect(await store.get(a.id)).toBeNull();
    expect(await store.get(b.id)).toBeNull();
    expect(await store.get(c.id)).not.toBeNull();
  });

  it('purgeExpired removes only expired rows and returns count', async () => {
    const store = createSessionStore(storage);
    const fresh = await store.create('u_1', 60_000);
    await storage.createUserSession({
      id: 'expired1',
      userId: 'u_1',
      expiresAt: new Date(Date.now() - 1_000),
    });
    await storage.createUserSession({
      id: 'expired2',
      userId: 'u_1',
      expiresAt: new Date(Date.now() - 2_000),
    });
    const purged = await store.purgeExpired(new Date());
    expect(purged).toBe(2);
    expect(await storage.getUserSession(fresh.id)).not.toBeNull();
    expect(await storage.getUserSession('expired1')).toBeNull();
    expect(await storage.getUserSession('expired2')).toBeNull();
  });
});
