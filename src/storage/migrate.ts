import { fileURLToPath } from 'node:url';
import type { BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { migrate as migrateSqlite } from 'drizzle-orm/better-sqlite3/migrator';
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import { migrate as migratePg } from 'drizzle-orm/node-postgres/migrator';

// drizzle-kit emits to drizzle/<dialect>/ at the project root (a sibling of src/).
const PG_FOLDER = fileURLToPath(new URL('../../drizzle/pg/', import.meta.url));
const SQLITE_FOLDER = fileURLToPath(new URL('../../drizzle/sqlite/', import.meta.url));

export async function runPgMigrations(db: NodePgDatabase): Promise<void> {
  await migratePg(db, { migrationsFolder: PG_FOLDER });
}

export function runSqliteMigrations(db: BetterSQLite3Database): void {
  migrateSqlite(db, { migrationsFolder: SQLITE_FOLDER });
}
