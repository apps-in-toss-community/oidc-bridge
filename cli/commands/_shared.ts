import { createService, type Service, type ServiceCtx } from '../../src/apps/service.js';
import type { Storage } from '../../src/storage/interface.js';
import { createSqliteStorage } from '../../src/storage/sqlite.js';
import { type ApiClient, createApiClient } from '../api-client.js';

export interface ConnectionOptions {
  apiUrl?: string;
  token?: string;
  dbPath?: string;
  asUser?: string;
}

export interface OnlineConnection {
  mode: 'online';
  client: ApiClient;
}

export interface OfflineConnection {
  mode: 'offline';
  service: Service;
  storage: Storage;
  ctx: ServiceCtx;
}

export type Connection = OnlineConnection | OfflineConnection;

export function connect(opts: ConnectionOptions): Connection {
  if (opts.dbPath) {
    const storage = createSqliteStorage({ path: opts.dbPath });
    const service = createService({ storage });
    if (!opts.asUser) {
      throw new Error('offline mode requires --as-user (the user_… id to act as)');
    }
    return { mode: 'offline', storage, service, ctx: { actorUserId: opts.asUser } };
  }
  if (!opts.apiUrl || !opts.token) {
    throw new Error('online mode requires --api-url and --token (or set --db-path for offline)');
  }
  return { mode: 'online', client: createApiClient({ baseUrl: opts.apiUrl, token: opts.token }) };
}

export async function close(c: Connection): Promise<void> {
  if (c.mode === 'offline') await c.storage.close();
}
