import { offlineStore } from '../bootstrap.js';
import { rest } from '../rest-client.js';

interface GlobalOpts {
  bridge?: string;
  adminToken?: string;
  offline?: boolean;
  dataDir?: string;
}

export async function tenantList(g: GlobalOpts): Promise<void> {
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    const tenants = await store.list();
    console.log(JSON.stringify({ tenants }, null, 2));
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  const out = await rest.listTenants({ bridge: g.bridge, adminToken: g.adminToken });
  console.log(JSON.stringify(out, null, 2));
}
