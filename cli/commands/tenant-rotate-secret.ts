import { offlineStore } from '../bootstrap.js';
import { rest } from '../rest-client.js';

interface GlobalOpts {
  bridge?: string;
  adminToken?: string;
  offline?: boolean;
  dataDir?: string;
}

export async function tenantRotateSecret(g: GlobalOpts, id: string): Promise<void> {
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    // TenantNotFoundError is propagated — index.ts .catch prints err.message.
    const { client_secret } = await store.rotateSecret(id);
    console.log(JSON.stringify({ client_secret }, null, 2));
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  const out = await rest.rotateSecret({ bridge: g.bridge, adminToken: g.adminToken }, id);
  console.log(JSON.stringify(out, null, 2));
}
