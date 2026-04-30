import type { Config } from '../config.js';
import { createFsStore } from './fs-store.js';
import type { TenantCreateInput, TenantPatch, TenantPublic, TenantRecord } from './types.js';

export class TenantNotFoundError extends Error {
  constructor(public tenantId: string) {
    super(`tenant ${tenantId} not found`);
    this.name = 'TenantNotFoundError';
  }
}

export interface CreatedTenant {
  tenant: TenantRecord;
  client_secret: string; // plaintext, returned once
}

export interface RotatedSecret {
  client_secret: string;
}

export interface TenantStore {
  get(tenantId: string): Promise<TenantRecord | null>;
  list(): Promise<TenantPublic[]>;
  create(input: TenantCreateInput): Promise<CreatedTenant>;
  update(tenantId: string, patch: TenantPatch): Promise<TenantRecord>;
  rotateSecret(tenantId: string): Promise<RotatedSecret>;
  delete(tenantId: string): Promise<void>;
}

/** Build the configured backend. GCPSM is lazy-imported. */
export async function createTenantStore(config: Config): Promise<TenantStore> {
  if (config.tenantStore.kind === 'fs') {
    return createFsStore(config.tenantStore.dataDir);
  }
  const { createGcpsmStore } = await import('./gcpsm-store.js');
  return createGcpsmStore(config.tenantStore.projectId);
}
