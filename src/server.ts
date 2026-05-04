import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { decryptColumn } from './apps/encryption.js';
import { loadBridgeFlags, loadOidcConfig, loadTossConfig } from './config.js';
import { createLogger } from './logger.js';
import { createMasterKeyProvider, deriveSealingKey } from './master-keys/index.js';
import { createAppSealingKeyResolver } from './oidc/app-sealing-key.js';
import { createInMemoryRevocationStore } from './oidc/revocation-store.js';
import { createSigningKeyRegistry } from './oidc/signing-keys.js';
import { createSessionService } from './sessions/service.js';
import { createSessionStore } from './sessions/store.js';
import type { Storage } from './storage/interface.js';
import { createPgStorage } from './storage/pg.js';
import { createSqliteStorage } from './storage/sqlite.js';
import type { TossAdapter } from './toss/adapter.js';
import { MockTossAdapter } from './toss/mock-adapter.js';
import { RealTossAdapter, type RealTossAdapterDeps } from './toss/real-adapter.js';

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

export function selectTossAdapter(
  env: NodeJS.ProcessEnv,
  deps: Omit<RealTossAdapterDeps, 'fetchImpl' | 'buildDispatcher'>,
): TossAdapter {
  if (env.BRIDGE_TOSS_ADAPTER === 'mock') return new MockTossAdapter();
  return new RealTossAdapter(deps);
}

interface MtlsAccessorDeps {
  storage: Storage;
  getMasterKey: (version: number) => Promise<Buffer>;
}

export function createMtlsMaterialAccessor(
  deps: MtlsAccessorDeps,
): (appId: string) => Promise<{ certPem: string; keyPem: string } | null> {
  return async (appId) => {
    const app = await deps.storage.getApp(appId);
    if (!app) return null;
    const masterKey = await deps.getMasterKey(app.sealingKeyVersion);
    const sealingKey = deriveSealingKey({ masterKey, appId });
    const aad = Buffer.from(appId, 'utf8');
    const certPem = decryptColumn({
      key: sealingKey,
      ciphertext: Buffer.from(app.mtlsCertEnc),
      aad,
    }).toString('utf8');
    const keyPem = decryptColumn({
      key: sealingKey,
      ciphertext: Buffer.from(app.mtlsKeyEnc),
      aad,
    }).toString('utf8');
    return { certPem, keyPem };
  };
}

export interface RunStartupTasksDeps {
  storage: Storage;
  now?: () => Date;
}

export interface StartupTaskResult {
  purgedSessions: number;
}

export async function runStartupTasks(deps: RunStartupTasksDeps): Promise<StartupTaskResult> {
  const now = (deps.now ?? (() => new Date()))();
  const purgedSessions = await deps.storage.purgeExpiredUserSessions(now);
  return { purgedSessions };
}

async function main() {
  const log = createLogger();
  const port = Number(process.env.PORT ?? 8080);

  const storage = await openStorage();
  const startupResult = await runStartupTasks({ storage });
  log.info({ purgedSessions: startupResult.purgedSessions }, 'startup tasks complete');

  const flags = loadBridgeFlags(process.env);
  log.info({ enableSessionLogin: flags.enableSessionLogin }, 'session-login flag');
  const session = flags.enableSessionLogin
    ? {
        service: createSessionService({
          store: createSessionStore(storage),
          ttlMs: 1000 * 60 * 60 * 24, // 24h
          lookupUser: async (email) => {
            const u = await storage.getUserByEmail(email);
            if (!u) return null;
            return { id: u.id, passwordHash: u.passwordHash };
          },
        }),
      }
    : undefined;

  const masterKeyProvider = createMasterKeyProvider();
  const oidcConfig = loadOidcConfig(process.env);
  const tossConfig = loadTossConfig(process.env);
  const signingKeyRegistry = await createSigningKeyRegistry({
    activeKid: oidcConfig.activeKid,
    signingKeys: oidcConfig.signingKeys,
  });
  const resolveAppSealingKey = createAppSealingKeyResolver({ provider: masterKeyProvider });

  const revocationStore = createInMemoryRevocationStore();

  const tossAdapter = selectTossAdapter(process.env, {
    apiBase: tossConfig.apiBase,
    getMtlsMaterial: createMtlsMaterialAccessor({
      storage,
      getMasterKey: (version) => masterKeyProvider.getKeyBytes(version),
    }),
  });

  const appOpts = {
    oidc: {
      config: oidcConfig,
      signingKeyRegistry,
      storage,
      tossAdapter,
      resolveAppSealingKey,
      revocationStore,
    },
    ...(session ? { session } : {}),
  };
  const app = createApp(appOpts);

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

// Only run main() when this file is the process entry point (i.e., production
// `node dist/server.mjs`). Importing server.ts in tests must not boot the HTTP
// listener.
const invokedAsEntrypoint = (() => {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  return import.meta.url === `file://${argv1}` || import.meta.url.endsWith(argv1);
})();

if (invokedAsEntrypoint) {
  main().catch((err) => {
    createLogger().fatal({ err }, 'oidc-bridge bootstrap failed');
    process.exit(1);
  });
}
