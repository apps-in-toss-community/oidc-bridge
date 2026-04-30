/**
 * Schema version of the tenant record on disk. Bumped only on
 * incompatible structural changes (see spec §5.2.6).
 */
export const CURRENT_SCHEMA_VERSION = 1 as const;

export interface ClientSecretHash {
  hash: string; // bcrypt, $2b$12$...
  created_at: number; // unix seconds
}

export interface TenantMTLS {
  cert_pem: string;
  key_pem: string;
  cert_fingerprint_sha256: string; // hex, lowercase
  expires_at: number; // unix seconds, parsed from cert NotAfter
}

export interface TenantRecord {
  schema_version: typeof CURRENT_SCHEMA_VERSION;
  id: string; // "tnt_..."
  name: string;
  environment: 'production' | 'sandbox';
  client_secret_hashes: ClientSecretHash[]; // 1..2 during rotation overlap
  mtls: TenantMTLS;
  sealing_key_version: number;
  created_at: number;
  updated_at: number;
}

/** Returned by list() — strips secret material. */
export interface TenantPublic {
  id: string;
  name: string;
  environment: 'production' | 'sandbox';
  mtls_fingerprint: string;
  mtls_expires_at: number;
  sealing_key_version: number;
  created_at: number;
  updated_at: number;
}

export interface TenantCreateInput {
  name: string;
  environment: 'production' | 'sandbox';
  cert_pem: string;
  key_pem: string;
}

export interface TenantPatch {
  name?: string;
  environment?: 'production' | 'sandbox';
  cert_pem?: string;
  key_pem?: string;
}
