import { Miniflare } from 'miniflare';
import { describe, expect, it } from 'vitest';
import { runStorageConformance } from './conformance.js';
import { createD1Storage, runD1Migrations } from './d1.js';

describe('D1Storage', () => {
  runStorageConformance('d1', {
    async open() {
      const mf = new Miniflare({
        modules: true,
        script: 'export default { fetch() { return new Response("ok"); } };',
        d1Databases: { DB: 'test-db' },
        d1Persist: false,
      });
      const db = await mf.getD1Database('DB');
      await runD1Migrations(db);
      return createD1Storage({ db, onClose: () => mf.dispose() });
    },
    async cleanup(s) {
      await s.close();
    },
  });

  it('runD1Migrations is idempotent — second call on an already-migrated DB does not throw', async () => {
    const mf = new Miniflare({
      modules: true,
      script: 'export default { fetch() { return new Response("ok"); } };',
      d1Databases: { DB: 'test-idempotent' },
      d1Persist: false,
    });
    try {
      const db = await mf.getD1Database('DB');
      await runD1Migrations(db);
      await expect(runD1Migrations(db)).resolves.toBeUndefined();
    } finally {
      await mf.dispose();
    }
  });
});
