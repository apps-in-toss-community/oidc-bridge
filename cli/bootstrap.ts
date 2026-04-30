import { createFsStore } from '../src/tenants/fs-store.js';
import type { TenantStore } from '../src/tenants/store.js';

/**
 * `--offline` mode opens an fs-store directly, no bridge process required.
 * Used to provision the very first tenant before booting the bridge.
 */
export async function offlineStore(dataDir: string): Promise<TenantStore> {
  return createFsStore(dataDir);
}
