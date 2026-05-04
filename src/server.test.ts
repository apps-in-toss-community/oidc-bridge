import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from './app.js';
import { encryptColumn } from './apps/encryption.js';
import { deriveSealingKey } from './master-keys/index.js';
import type { MasterKeyProvider } from './master-keys/provider.js';
import {
  buildAdminBlock,
  createMtlsMaterialAccessor,
  runStartupTasks,
  selectTossAdapter,
} from './server.js';
import { createSessionService } from './sessions/service.js';
import { createSessionStore } from './sessions/store.js';
import type { Storage } from './storage/interface.js';
import { createSqliteStorage } from './storage/sqlite.js';
import type { AppRecord } from './storage/types.js';
import { MockTossAdapter } from './toss/mock-adapter.js';
import { RealTossAdapter } from './toss/real-adapter.js';

describe('selectTossAdapter', () => {
  const orig = { ...process.env };
  beforeEach(() => {
    delete process.env.BRIDGE_TOSS_ADAPTER;
  });
  afterEach(() => {
    process.env = { ...orig };
  });

  const deps = {
    apiBase: 'https://x.example',
    getMtlsMaterial: async () => null,
  };

  it('mock when BRIDGE_TOSS_ADAPTER=mock', () => {
    process.env.BRIDGE_TOSS_ADAPTER = 'mock';
    expect(selectTossAdapter(process.env, deps)).toBeInstanceOf(MockTossAdapter);
  });

  it('real otherwise', () => {
    expect(selectTossAdapter(process.env, deps)).toBeInstanceOf(RealTossAdapter);
  });
});

describe('createMtlsMaterialAccessor', () => {
  it('round-trips: encrypts cert+key into AppRecord, decrypts to PEM strings', async () => {
    const masterKey = randomBytes(32);
    const appId = 'app_test_001';
    const sealingKey = deriveSealingKey({ masterKey, appId });
    const aad = Buffer.from(appId, 'utf8');
    const certPem = '-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----\n';
    const keyPem = '-----BEGIN PRIVATE KEY-----\nGHIJKL\n-----END PRIVATE KEY-----\n';
    const certEnc = encryptColumn({ key: sealingKey, plaintext: Buffer.from(certPem), aad });
    const keyEnc = encryptColumn({ key: sealingKey, plaintext: Buffer.from(keyPem), aad });

    const fakeApp: AppRecord = {
      id: appId,
      sealingKeyVersion: 1,
      mtlsCertEnc: certEnc,
      mtlsKeyEnc: keyEnc,
    } as unknown as AppRecord;
    const storage = { getApp: async (id: string) => (id === appId ? fakeApp : null) } as Storage;

    const accessor = createMtlsMaterialAccessor({
      storage,
      getMasterKey: async () => masterKey,
    });
    const out = await accessor(appId);
    expect(out).toEqual({ certPem, keyPem });
    expect(await accessor('missing')).toBeNull();
  });
});

describe('runStartupTasks', () => {
  let dir: string;
  let storage: Storage;

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-startup-'));
    storage = createSqliteStorage({ path: join(dir, 'test.db') });
    await storage.createUser({ id: 'user_a', email: 'a@x.com' });
  });

  afterEach(async () => {
    await storage.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('purges expired user_sessions and returns the count', async () => {
    const now = new Date('2026-05-03T00:00:00Z');
    await storage.createUserSession({
      id: 'sess_expired',
      userId: 'user_a',
      expiresAt: new Date('2026-05-02T00:00:00Z'),
    });
    await storage.createUserSession({
      id: 'sess_live',
      userId: 'user_a',
      expiresAt: new Date('2026-05-04T00:00:00Z'),
    });
    const result = await runStartupTasks({ storage, now: () => now });
    expect(result.purgedSessions).toBe(1);
    expect(await storage.getUserSession('sess_expired')).toBeNull();
    expect(await storage.getUserSession('sess_live')).not.toBeNull();
  });

  it('returns 0 when nothing to purge', async () => {
    const result = await runStartupTasks({ storage, now: () => new Date() });
    expect(result.purgedSessions).toBe(0);
  });
});

describe('buildAdminBlock', () => {
  let storage: Storage;
  const fakeProvider: MasterKeyProvider = {
    getKeyBytes: async () => Buffer.alloc(32),
    listVersions: async () => [1],
  };

  beforeEach(async () => {
    storage = createSqliteStorage({ path: ':memory:' });
  });
  afterEach(async () => {
    await storage.close();
  });

  it('returns a block when at least one non-retired master key exists', async () => {
    await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
    const block = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: {},
    });
    expect(block).not.toBeNull();
    if (!block) throw new Error('unreachable');
    expect(block.activeMasterKeyVersion()).toBe(1);
    expect(block.stage()).toBeUndefined();
    expect(block.masterKeyProvider).toBe(fakeProvider);
    expect(typeof block.service.workspaces.create).toBe('function');
  });

  it('picks the highest non-retired version when multiple exist', async () => {
    await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
    await storage.createMasterKey({ id: 'mk_2', version: 2, providerRef: 'env:2' });
    await storage.createMasterKey({ id: 'mk_3', version: 3, providerRef: 'env:3' });
    await storage.retireMasterKey(3, new Date());
    const block = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: {},
    });
    if (!block) throw new Error('expected block');
    expect(block.activeMasterKeyVersion()).toBe(2);
  });

  it('returns null when no master keys are present (pre-bootstrap)', async () => {
    const block = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: {},
    });
    expect(block).toBeNull();
  });

  it('returns null when every master key is retired', async () => {
    await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
    await storage.retireMasterKey(1, new Date());
    const block = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: {},
    });
    expect(block).toBeNull();
  });

  it('reads BRIDGE_STAGE for the stage callback', async () => {
    await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
    const block = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: { BRIDGE_STAGE: 'beta' },
    });
    if (!block) throw new Error('expected block');
    expect(block.stage()).toBe('beta');
  });

  it('ignores invalid BRIDGE_STAGE values (treated as undefined)', async () => {
    await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
    const block = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: { BRIDGE_STAGE: 'production' },
    });
    if (!block) throw new Error('expected block');
    expect(block.stage()).toBeUndefined();
  });
});

describe('admin routes mounted via buildAdminBlock + createApp', () => {
  let storage: Storage;
  const fakeProvider: MasterKeyProvider = {
    getKeyBytes: async () => Buffer.alloc(32),
    listVersions: async () => [1],
  };

  beforeEach(async () => {
    storage = createSqliteStorage({ path: ':memory:' });
    await storage.createMasterKey({ id: 'mk_1', version: 1, providerRef: 'env:1' });
  });
  afterEach(async () => {
    await storage.close();
  });

  it('GET /admin/workspaces without token returns 401 (route mounted, auth wired)', async () => {
    const admin = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: {},
    });
    if (!admin) throw new Error('expected admin block');
    const app = createApp({ admin });
    const r = await app.request('/admin/workspaces');
    expect(r.status).toBe(401);
  });

  it('GET /admin/workspaces with bogus token returns 401 (not 404)', async () => {
    const admin = await buildAdminBlock({
      storage,
      masterKeyProvider: fakeProvider,
      env: {},
    });
    if (!admin) throw new Error('expected admin block');
    const app = createApp({ admin });
    const r = await app.request('/admin/workspaces', {
      headers: { authorization: 'Bearer not-a-real-token' },
    });
    expect(r.status).toBe(401);
  });
});

describe('server session wiring — flag-on path', () => {
  let storage: Storage;

  beforeEach(async () => {
    storage = createSqliteStorage({ path: ':memory:' });
    await storage.createUser({ id: 'user_a', email: 'a@x.com' });
  });

  afterEach(async () => {
    await storage.close();
  });

  it('flag-on: POST /admin/login returns non-404 (route is mounted)', async () => {
    const app = createApp({
      session: {
        service: createSessionService({
          store: createSessionStore(storage),
          ttlMs: 1000 * 60 * 60 * 24,
          lookupUser: async (email) => {
            const u = await storage.getUserByEmail(email);
            if (!u) return null;
            return { id: u.id, passwordHash: u.passwordHash };
          },
        }),
      },
    });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@x.com', password: 'wrong' }),
    });
    // 401 (invalid_credentials or no_password_set) proves the route is mounted, not 404.
    expect(r.status).not.toBe(404);
    expect([400, 401]).toContain(r.status);
  });

  it('flag-off: POST /admin/login returns 404 (route not mounted)', async () => {
    const app = createApp();
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@x.com', password: 'wrong' }),
    });
    expect(r.status).toBe(404);
  });
});
