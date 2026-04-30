import { readFile } from 'node:fs/promises';
import { publicView } from '../../src/tenants/public-view.js';
import { offlineStore } from '../bootstrap.js';
import { rest } from '../rest-client.js';

interface GlobalOpts {
  bridge?: string;
  adminToken?: string;
  offline?: boolean;
  dataDir?: string;
}

interface CreateOpts {
  name: string;
  environment: 'production' | 'sandbox';
  cert: string;
  key: string;
}

export async function tenantCreate(g: GlobalOpts, opts: CreateOpts): Promise<void> {
  const cert_pem = await readFile(opts.cert, 'utf8');
  const key_pem = await readFile(opts.key, 'utf8');
  const body = { name: opts.name, environment: opts.environment, cert_pem, key_pem };
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    const created = await store.create(body);
    console.log(
      JSON.stringify(
        {
          tenant: publicView(created.tenant),
          client_id: created.tenant.id,
          client_secret: created.client_secret,
        },
        null,
        2,
      ),
    );
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  const out = await rest.createTenant({ bridge: g.bridge, adminToken: g.adminToken }, body);
  console.log(JSON.stringify(out, null, 2));
}
