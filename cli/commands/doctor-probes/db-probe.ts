import { existsSync } from 'node:fs';
import { createPgStorage } from '../../../src/storage/pg.js';
import { createSqliteStorage } from '../../../src/storage/sqlite.js';
import type { ProbeItem } from '../../output.js';

export type DbProbeOpts =
  | { storage: 'sqlite'; sqlitePath: string }
  | { storage: 'pg'; connectionString: string };

export async function runDbProbe(opts: DbProbeOpts): Promise<ProbeItem> {
  if (opts.storage === 'sqlite') {
    return probeSqlite(opts.sqlitePath);
  }
  return probePg(opts.connectionString);
}

async function probeSqlite(sqlitePath: string): Promise<ProbeItem> {
  const preexisting = existsSync(sqlitePath);
  let storage: Awaited<ReturnType<typeof createSqliteStorage>> | undefined;
  try {
    storage = createSqliteStorage({ path: sqlitePath });
    // Smoke read — exercises the migrated schema.
    await storage.listMasterKeys();
    if (!preexisting) {
      return {
        name: 'db',
        state: 'yellow',
        detail: `sqlite: created and migrated ${sqlitePath}`,
      };
    }
    return { name: 'db', state: 'green', detail: `sqlite: ${sqlitePath} reachable` };
  } catch (err) {
    return { name: 'db', state: 'red', detail: `sqlite: ${(err as Error).message}` };
  } finally {
    if (storage) await storage.close().catch(() => undefined);
  }
}

async function probePg(connectionString: string): Promise<ProbeItem> {
  let storage: Awaited<ReturnType<typeof createPgStorage>> | undefined;
  try {
    storage = await createPgStorage({ connectionString });
    await storage.listMasterKeys();
    return { name: 'db', state: 'green', detail: 'pg: reachable + migrated' };
  } catch (err) {
    return { name: 'db', state: 'red', detail: `pg: ${(err as Error).message}` };
  } finally {
    if (storage) await storage.close().catch(() => undefined);
  }
}
