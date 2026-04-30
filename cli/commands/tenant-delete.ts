import { offlineStore } from '../bootstrap.js';
import { rest } from '../rest-client.js';

interface GlobalOpts {
  bridge?: string;
  adminToken?: string;
  offline?: boolean;
  dataDir?: string;
}

export async function tenantDelete(g: GlobalOpts, id: string): Promise<void> {
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    // delete is idempotent in fs-store (no throw on missing id).
    await store.delete(id);
    console.log(JSON.stringify({ deleted: id }, null, 2));
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  await rest.deleteTenant({ bridge: g.bridge, adminToken: g.adminToken }, id);
  console.log(JSON.stringify({ deleted: id }, null, 2));
}
