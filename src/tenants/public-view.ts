import type { TenantPublic, TenantRecord } from './types.js';

/** Strips secret material from a TenantRecord, matching the admin REST publicView shape. */
export function publicView(t: TenantRecord): TenantPublic {
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
