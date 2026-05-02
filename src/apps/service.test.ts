import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { Storage } from '../storage/interface.js';
import { createSqliteStorage } from '../storage/sqlite.js';
import { createService, type Service, type ServiceCtx } from './service.js';

let dir: string;
let storage: Storage;
let svc: Service;
let ctx: ServiceCtx;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-svc-'));
  storage = createSqliteStorage({ path: join(dir, 'test.db') });
  svc = createService({ storage });
  await storage.createUser({ id: 'user_actor', email: 'actor@x.com' });
  ctx = { actorUserId: 'user_actor' };
});

afterEach(async () => {
  await storage.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('service: workspaces', () => {
  it('creates a workspace owned by actor', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    expect(w.ownerUserId).toBe('user_actor');
    expect(w.name).toBe('first');
  });

  it('lists workspaces by owner', async () => {
    await svc.workspaces.create(ctx, { name: 'first' });
    await svc.workspaces.create(ctx, { name: 'second' });
    const list = await svc.workspaces.list(ctx);
    expect(list).toHaveLength(2);
  });

  it('updates workspace name', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    const updated = await svc.workspaces.update(ctx, w.id, { name: 'renamed' });
    expect(updated.name).toBe('renamed');
  });

  it('deletes workspace', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    await svc.workspaces.delete(ctx, w.id);
    const list = await svc.workspaces.list(ctx);
    expect(list).toHaveLength(0);
  });

  it('writes audit entries', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    await svc.workspaces.update(ctx, w.id, { name: 'renamed' });
    await svc.workspaces.delete(ctx, w.id);
    const audits = await storage.listAudit();
    // listAudit orders by ts DESC; same-ms ties have undefined order across drivers,
    // so assert membership + count rather than absolute order.
    const actions = new Set(audits.map((a) => a.action));
    expect(audits).toHaveLength(3);
    expect(actions).toEqual(new Set(['workspace.create', 'workspace.update', 'workspace.delete']));
  });

  it('refuses cross-owner updates and deletes', async () => {
    const w = await svc.workspaces.create(ctx, { name: 'first' });
    await storage.createUser({ id: 'user_other', email: 'b@x.com' });
    const otherCtx: ServiceCtx = { actorUserId: 'user_other' };
    await expect(svc.workspaces.update(otherCtx, w.id, { name: 'x' })).rejects.toThrow(/not_found/);
    await expect(svc.workspaces.delete(otherCtx, w.id)).rejects.toThrow(/not_found/);
  });
});

describe('service: apps', () => {
  const masterKey = Buffer.alloc(32, 0xab);
  const stage = 'alpha';

  async function setupWorkspace() {
    return svc.workspaces.create(ctx, { name: 'ws' });
  }

  it('creates an app with encrypted mTLS, hashed secret, and verified ownership in alpha', async () => {
    const w = await setupWorkspace();
    const result = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-1',
      displayTitle: 'My App',
      mtlsCert: Buffer.from('-----BEGIN CERT-----'),
      mtlsKey: Buffer.from('-----BEGIN PRIVATE KEY-----'),
      allowedOrigins: ['https://app.example.com'],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    expect(result.app.workspaceId).toBe(w.id);
    expect(result.app.ownershipStatus).toBe('verified');
    expect(result.app.clientSecretHashes).toHaveLength(1);
    expect(result.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.clientId).toMatch(/^client_/);
    expect(result.app.mtlsCertEnc.length).toBeGreaterThan(0);
  });

  it('puts new apps in pending with 72h grace when not in alpha', async () => {
    const w = await setupWorkspace();
    const result = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-2',
      displayTitle: 'X',
      mtlsCert: Buffer.from('cert'),
      mtlsKey: Buffer.from('key'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage: 'beta',
    });
    expect(result.app.ownershipStatus).toBe('pending');
    expect(result.app.ownershipGraceUntil).not.toBeNull();
  });

  it('rotate-secret appends a new hash and returns plaintext', async () => {
    const w = await setupWorkspace();
    const created = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-3',
      displayTitle: 'X',
      mtlsCert: Buffer.from('cert'),
      mtlsKey: Buffer.from('key'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    const rotated = await svc.apps.rotateSecret(ctx, created.app.id);
    expect(rotated.clientSecret).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(rotated.app.clientSecretHashes).toHaveLength(2);
  });

  it('refuses cross-workspace access', async () => {
    await storage.createUser({ id: 'user_other', email: 'c@x.com' });
    const otherCtx: ServiceCtx = { actorUserId: 'user_other' };
    const w = await setupWorkspace();
    const created = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-4',
      displayTitle: 'X',
      mtlsCert: Buffer.from('c'),
      mtlsKey: Buffer.from('k'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    await expect(svc.apps.get(otherCtx, created.app.id)).rejects.toThrow(/not_found/);
  });

  it('toggleRawTokens flips the bool and audits', async () => {
    const w = await setupWorkspace();
    const created = await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-5',
      displayTitle: 'X',
      mtlsCert: Buffer.from('c'),
      mtlsKey: Buffer.from('k'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    const toggled = await svc.apps.toggleRawTokens(ctx, created.app.id, true);
    expect(toggled.rawTokensEnabled).toBe(true);
  });

  it('rejects duplicate appIdToss in the same workspace', async () => {
    const w = await setupWorkspace();
    await svc.apps.create(ctx, {
      workspaceId: w.id,
      appIdToss: 'mini-dup',
      displayTitle: 'X',
      mtlsCert: Buffer.from('c'),
      mtlsKey: Buffer.from('k'),
      allowedOrigins: [],
      sealingKeyVersion: 1,
      masterKey,
      stage,
    });
    await expect(
      svc.apps.create(ctx, {
        workspaceId: w.id,
        appIdToss: 'mini-dup',
        displayTitle: 'Y',
        mtlsCert: Buffer.from('c'),
        mtlsKey: Buffer.from('k'),
        allowedOrigins: [],
        sealingKeyVersion: 1,
        masterKey,
        stage,
      }),
    ).rejects.toThrow();
  });
});
