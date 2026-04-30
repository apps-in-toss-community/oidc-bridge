import { publicView } from '../../src/tenants/public-view.js';
import { offlineStore } from '../bootstrap.js';
import { rest } from '../rest-client.js';

interface GlobalOpts {
  bridge?: string;
  adminToken?: string;
  offline?: boolean;
  dataDir?: string;
}

export async function tenantShow(g: GlobalOpts, id: string): Promise<void> {
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    const t = await store.get(id);
    if (!t) throw new Error(`tenant ${id} not found`);
    console.log(JSON.stringify(publicView(t), null, 2));
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  const out = await rest.getTenant({ bridge: g.bridge, adminToken: g.adminToken }, id);
  console.log(JSON.stringify(out, null, 2));
}
