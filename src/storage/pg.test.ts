import { Pool } from 'pg';
import { describe } from 'vitest';
import { runStorageConformance } from './conformance.js';
import { createPgStorage } from './pg.js';

const url = process.env.PG_TEST_URL;

if (!url) {
  describe.skip('Storage conformance — pg (PG_TEST_URL not set)', () => {});
} else {
  runStorageConformance('pg', {
    async open() {
      // Truncate before each open to give the conformance suite an empty DB.
      const pool = new Pool({ connectionString: url });
      try {
        // Apply migrations once so the tables exist; the driver will re-run idempotently.
        const { drizzle } = await import('drizzle-orm/node-postgres');
        const { runPgMigrations } = await import('./migrate.js');
        await runPgMigrations(drizzle(pool));
        await pool.query(
          'TRUNCATE TABLE audit_log, master_keys, user_sessions, apps, workspaces, api_tokens, users RESTART IDENTITY CASCADE',
        );
      } finally {
        await pool.end();
      }
      return createPgStorage({ connectionString: url });
    },
    async cleanup(s) {
      await s.close();
    },
  });
}
