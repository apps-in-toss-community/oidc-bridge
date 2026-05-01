import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runSqliteMigrations } from './migrate.js';

describe('runSqliteMigrations', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-migrate-'));
    dbPath = join(dir, 'test.db');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('applies all migrations on a fresh DB', () => {
    const db = new Database(dbPath);
    runSqliteMigrations(db);
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as { name: string }[];
    const names = tables.map((t) => t.name).filter((n) => !n.startsWith('sqlite_'));
    expect(names).toEqual([
      'api_tokens',
      'apps',
      'audit_log',
      'master_keys',
      'schema_migrations',
      'user_sessions',
      'users',
      'workspaces',
    ]);
    db.close();
  });

  it('is idempotent', () => {
    const db = new Database(dbPath);
    runSqliteMigrations(db);
    runSqliteMigrations(db);
    const applied = db.prepare('SELECT filename FROM schema_migrations').all() as {
      filename: string;
    }[];
    expect(applied.map((r) => r.filename)).toEqual(['001_initial.sqlite.sql']);
    db.close();
  });
});
