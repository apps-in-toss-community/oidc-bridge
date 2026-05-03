import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
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
    const sqlite = new Database(dbPath);
    const db = drizzle(sqlite);
    runSqliteMigrations(db);
    const tables = sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as { name: string }[];
    const names = tables.map((t) => t.name).filter((n) => !n.startsWith('sqlite_'));
    expect(names).toContain('users');
    expect(names).toContain('api_tokens');
    expect(names).toContain('workspaces');
    expect(names).toContain('apps');
    expect(names).toContain('user_sessions');
    expect(names).toContain('master_keys');
    expect(names).toContain('audit_log');
    expect(names).toContain('__drizzle_migrations');
    sqlite.close();
  });

  it('is idempotent', () => {
    const sqlite = new Database(dbPath);
    const db = drizzle(sqlite);
    runSqliteMigrations(db);
    runSqliteMigrations(db);
    const applied = sqlite.prepare('SELECT hash FROM __drizzle_migrations ORDER BY id').all() as {
      hash: string;
    }[];
    expect(applied.length).toBeGreaterThanOrEqual(1);
    sqlite.close();
  });

  it('users.password_hash column exists', () => {
    const sqlite = new Database(dbPath);
    const db = drizzle(sqlite);
    runSqliteMigrations(db);
    const cols = sqlite.prepare('PRAGMA table_info(users)').all() as { name: string }[];
    expect(cols.map((c) => c.name)).toContain('password_hash');
    sqlite.close();
  });
});
