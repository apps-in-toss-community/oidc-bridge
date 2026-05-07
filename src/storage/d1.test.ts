import { Miniflare } from 'miniflare';
import { describe } from 'vitest';
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
});
