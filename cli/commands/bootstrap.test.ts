import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { createSqliteStorage } from '../../src/storage/sqlite.js';
import { formatBootstrapSummary, runBootstrap } from './bootstrap.js';

describe('runBootstrap', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'bridge-bootstrap-'));
  });

  it('happy path creates DB + master key file + user + token + workspace', async () => {
    const dbPath = join(tmp, 'bridge.db');
    const masterKeyDir = join(tmp, 'keys');
    const summary = await runBootstrap({
      dbPath,
      masterKeyDir,
      email: 'a@b',
      workspaceName: 'default',
    });

    expect(summary.userId).toMatch(/^user_/);
    expect(summary.workspaceId).toMatch(/^ws_/);
    expect(summary.apiTokenId).toMatch(/^tok_/);
    expect(summary.apiTokenPlaintext).toMatch(/^tok_/);
    expect(summary.masterKeyVersion).toBe(1);

    const masterKeyPath = join(masterKeyDir, 'v1.key');
    expect(summary.masterKeyPath).toBe(masterKeyPath);
    const stat = statSync(masterKeyPath);
    expect(stat.mode & 0o777).toBe(0o600);
    expect(readFileSync(masterKeyPath).length).toBe(32);

    const storage = createSqliteStorage({ path: dbPath });
    try {
      const user = await storage.getUserById(summary.userId);
      expect(user?.email).toBe('a@b');
      const ws = await storage.getWorkspace(summary.workspaceId);
      expect(ws?.name).toBe('default');
      expect(ws?.ownerUserId).toBe(summary.userId);
      const tokens = await storage.listApiTokensByUser(summary.userId);
      expect(tokens).toHaveLength(1);
      expect(tokens[0]?.id).toBe(summary.apiTokenId);
      // Hash row must not equal plaintext.
      expect(tokens[0]?.tokenHash).not.toBe(summary.apiTokenPlaintext);
      const masterKeys = await storage.listMasterKeys();
      expect(masterKeys).toHaveLength(1);
      expect(masterKeys[0]?.version).toBe(1);
      expect(masterKeys[0]?.providerRef).toBe(`file:${masterKeyPath}`);
    } finally {
      await storage.close();
    }
  });

  it('refuses to run if users table already has rows', async () => {
    const dbPath = join(tmp, 'bridge.db');
    const masterKeyDir = join(tmp, 'keys');
    await runBootstrap({ dbPath, masterKeyDir, email: 'a@b', workspaceName: 'first' });
    const masterKeyDir2 = join(tmp, 'keys2');
    await expect(
      runBootstrap({
        dbPath,
        masterKeyDir: masterKeyDir2,
        email: 'second@b',
        workspaceName: 'second',
      }),
    ).rejects.toThrow(/already bootstrapped/);
  });

  it('refuses to overwrite an existing master-key file', async () => {
    const dbPath = join(tmp, 'bridge.db');
    const masterKeyDir = join(tmp, 'keys');
    await runBootstrap({ dbPath, masterKeyDir, email: 'a@b', workspaceName: 'first' });
    // Second run with a fresh DB but same key dir.
    const dbPath2 = join(tmp, 'bridge2.db');
    await expect(
      runBootstrap({ dbPath: dbPath2, masterKeyDir, email: 'b@x', workspaceName: 'w' }),
    ).rejects.toThrow(/master key already exists/);
  });

  it('--password sets passwordHash on the new user', async () => {
    const dbPath = join(tmp, 'bridge.db');
    const masterKeyDir = join(tmp, 'keys');
    const summary = await runBootstrap({
      dbPath,
      masterKeyDir,
      email: 'a@b',
      workspaceName: 'w',
      password: 'hunter2',
    });
    const storage = createSqliteStorage({ path: dbPath });
    try {
      const user = await storage.getUserById(summary.userId);
      expect(user?.passwordHash).toBeTruthy();
      expect(user?.passwordHash).not.toBe('hunter2');
    } finally {
      await storage.close();
    }
  });

  it('writes the master-key file inside the requested directory (creates if missing)', async () => {
    const dbPath = join(tmp, 'bridge.db');
    const masterKeyDir = join(tmp, 'nested', 'deeper', 'keys');
    await runBootstrap({ dbPath, masterKeyDir, email: 'a@b', workspaceName: 'w' });
    expect(existsSync(join(masterKeyDir, 'v1.key'))).toBe(true);
  });
});

describe('formatBootstrapSummary', () => {
  const summary = {
    userId: 'user_test123',
    workspaceId: 'ws_test456',
    apiTokenId: 'tok_testid',
    apiTokenPlaintext: 'tok_supersecretplaintext',
    masterKeyVersion: 1,
    masterKeyPath: '/data/keys/v1.key',
  };
  const env = { issuerHint: 'https://oidc-bridge.example', dbPath: '/data/bridge.db' };

  it('prints apiTokenPlaintext exactly once', () => {
    const out = formatBootstrapSummary(summary, env);
    // split-by produces N+1 parts; N=1 means exactly one occurrence
    expect(out.split(summary.apiTokenPlaintext).length).toBe(2);
  });

  it('contains ADMIN_API_TOKEN with the plaintext value', () => {
    const out = formatBootstrapSummary(summary, env);
    expect(out).toContain(`ADMIN_API_TOKEN=${summary.apiTokenPlaintext}`);
  });

  it('contains API_TOKEN placeholder (not the plaintext)', () => {
    const out = formatBootstrapSummary(summary, env);
    expect(out).toContain('API_TOKEN=<paste ADMIN_API_TOKEN above>');
  });
});
