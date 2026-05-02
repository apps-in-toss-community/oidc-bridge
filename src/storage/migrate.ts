import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { migrate as migrateSqlite } from 'drizzle-orm/better-sqlite3/migrator';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { migrate as migratePg } from 'drizzle-orm/node-postgres/migrator';

// drizzle-kit emits to drizzle/<dialect>/ at the project root. We anchor at
// the nearest ancestor directory that has both `package.json` and `drizzle/`,
// so the resolution survives bundling: the source file lives at
// `src/storage/migrate.ts` (project root is two levels up) but the bundled
// CLI lives at `dist/index.mjs` (project root is one level up). A walk
// upward gives the same answer in both cases.
function findProjectRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    if (existsSync(join(dir, 'package.json')) && existsSync(join(dir, 'drizzle'))) {
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    `runMigrations: could not locate project root (package.json + drizzle/) above ${fileURLToPath(import.meta.url)}`,
  );
}

const PROJECT_ROOT = findProjectRoot();
const PG_FOLDER = join(PROJECT_ROOT, 'drizzle/pg');
const SQLITE_FOLDER = join(PROJECT_ROOT, 'drizzle/sqlite');

export async function runPgMigrations(db: NodePgDatabase): Promise<void> {
  await migratePg(db, { migrationsFolder: PG_FOLDER });
}

export function runSqliteMigrations(db: BetterSQLite3Database): void {
  migrateSqlite(db, { migrationsFolder: SQLITE_FOLDER });
}
