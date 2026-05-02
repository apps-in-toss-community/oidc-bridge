import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runStorageConformance } from './conformance.js';
import { createSqliteStorage } from './sqlite.js';

let dir: string | null = null;

runStorageConformance('sqlite', {
  async open() {
    dir = mkdtempSync(join(tmpdir(), 'oidc-bridge-sqlite-'));
    return createSqliteStorage({ path: join(dir, 'test.db') });
  },
  async cleanup(s) {
    await s.close();
    if (dir) {
      rmSync(dir, { recursive: true, force: true });
      dir = null;
    }
  },
});
