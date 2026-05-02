import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

// This test exercises the bundled CLI as a real subprocess. The migration
// path resolution in src/storage/migrate.ts has to work both when imported
// from source (vitest) and when bundled into dist/index.mjs — those resolve
// `import.meta.url` to different locations. Vitest-only tests can't catch
// the regression.

const REPO_ROOT = new URL('..', import.meta.url).pathname;
const CLI = join(REPO_ROOT, 'dist/index.mjs');

describe('bundled CLI offline mode', () => {
  let dir: string;
  let dbPath: string;

  beforeAll(() => {
    if (!existsSync(CLI)) {
      execFileSync('pnpm', ['build:cli'], { cwd: REPO_ROOT, stdio: 'inherit' });
    }
    dir = mkdtempSync(join(tmpdir(), 'oidc-cli-bundled-'));
    dbPath = join(dir, 'qa.db');
  }, 120_000);

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it('runs migrations + lists workspaces from bundled dist/index.mjs', () => {
    rmSync(dbPath, { force: true });

    const result = spawnSync(
      'node',
      [CLI, 'workspace', 'list', '--db-path', dbPath, '--as-user', 'user_qa'],
      { encoding: 'utf8', cwd: REPO_ROOT },
    );

    expect(result.stderr).not.toMatch(/Can't find meta\/_journal\.json/);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe('');

    const verify = new Database(dbPath, { readonly: true });
    const tables = verify
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as { name: string }[];
    verify.close();
    const names = tables.map((t) => t.name);
    expect(names).toContain('workspaces');
    expect(names).toContain('users');
  });
});
