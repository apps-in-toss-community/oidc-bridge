import type { TenantRecord } from '../../src/tenants/types.js';
import { offlineStore } from '../bootstrap.js';
import { rest } from '../rest-client.js';

interface GlobalOpts {
  bridge?: string;
  adminToken?: string;
  offline?: boolean;
  dataDir?: string;
}

/** Strips secret material from a TenantRecord, matching the admin REST publicView shape. */
function publicView(t: TenantRecord) {
  return {
    id: t.id,
    name: t.name,
    environment: t.environment,
    mtls_fingerprint: t.mtls.cert_fingerprint_sha256,
    mtls_expires_at: t.mtls.expires_at,
    sealing_key_version: t.sealing_key_version,
    created_at: t.created_at,
    updated_at: t.updated_at,
  };
}

export async function tenantShow(g: GlobalOpts, id: string): Promise<void> {
  if (g.offline) {
    if (!g.dataDir) throw new Error('--data-dir is required with --offline');
    const store = await offlineStore(g.dataDir);
    const t = await store.get(id);
    if (!t) {
      process.stderr.write(`error: tenant ${id} not found\n`);
      process.exit(1);
    }
    console.log(JSON.stringify(publicView(t), null, 2));
    return;
  }
  if (!g.bridge || !g.adminToken) throw new Error('--bridge and --admin-token required');
  const out = await rest.getTenant({ bridge: g.bridge, adminToken: g.adminToken }, id);
  console.log(JSON.stringify(out, null, 2));
}
