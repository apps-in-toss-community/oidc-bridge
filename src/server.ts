import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { loadOidcConfig } from './config.js';
import { createLogger } from './logger.js';
import { createMasterKeyProvider } from './master-keys/index.js';
import { createAppSealingKeyResolver } from './oidc/app-sealing-key.js';
import { createInMemoryRevocationStore } from './oidc/revocation-store.js';
import { createSigningKeyRegistry } from './oidc/signing-keys.js';
import type { Storage } from './storage/interface.js';
import { createPgStorage } from './storage/pg.js';
import { createSqliteStorage } from './storage/sqlite.js';
import { MockTossAdapter } from './toss/mock-adapter.js';

async function openStorage(): Promise<Storage> {
  const kind = (process.env.STORAGE ?? 'sqlite').toLowerCase();
  if (kind === 'pg') {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error('STORAGE=pg requires DATABASE_URL');
    return createPgStorage({ connectionString: url });
  }
  if (kind === 'sqlite') {
    const path = process.env.SQLITE_PATH ?? './data/oidc-bridge.sqlite';
    // Ensure the parent directory exists (e.g. /app/data/ in Docker).
    mkdirSync(dirname(path), { recursive: true });
    return createSqliteStorage({ path });
  }
  throw new Error(`unknown STORAGE=${kind}`);
}

async function main() {
  const log = createLogger();
  const port = Number(process.env.PORT ?? 8080);

  const storage = await openStorage();
  const masterKeyProvider = createMasterKeyProvider();
  const oidcConfig = loadOidcConfig(process.env);
  const signingKeyRegistry = await createSigningKeyRegistry({
    activeKid: oidcConfig.activeKid,
    signingKeys: oidcConfig.signingKeys,
  });
  const resolveAppSealingKey = createAppSealingKeyResolver({ provider: masterKeyProvider });

  const revocationStore = createInMemoryRevocationStore();

  const app = createApp({
    oidc: {
      config: oidcConfig,
      signingKeyRegistry,
      storage,
      tossAdapter: new MockTossAdapter(),
      resolveAppSealingKey,
      revocationStore,
    },
  });

  serve({ fetch: app.fetch, port }, (info) => {
    log.info({ port: info.port, addr: info.address }, 'oidc-bridge listening');
  });

  const shutdown = (signal: NodeJS.Signals) => {
    log.info({ signal }, 'received shutdown signal');
    void storage.close().finally(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  createLogger().fatal({ err }, 'oidc-bridge bootstrap failed');
  process.exit(1);
});
