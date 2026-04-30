import {
  certFingerprintSha256,
  certNotAfterUnix,
  generateClientSecret,
  generateTenantId,
  hashClientSecret,
} from './crypto.js';
import {
  CURRENT_SCHEMA_VERSION,
  type TenantCreateInput,
  type TenantPatch,
  type TenantPublic,
  type TenantRecord,
} from './types.js';

/** Regex a valid tenant id must match. */
export const TENANT_ID_PATTERN = /^tnt_[0-9a-hjkmnp-tv-z]{24}$/;

/**
 * How long (in seconds) both old and new client_secret hashes remain valid
 * during a rotation. After this window the old hash is dropped.
 */
export const ROTATION_OVERLAP_SECONDS = 72 * 3600;

/** Strip secret material from a TenantRecord for list / show responses. */
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

/** Build a fresh TenantRecord + plaintext client_secret from create input. */
export async function buildNewTenantRecord(
  input: TenantCreateInput,
): Promise<{ record: TenantRecord; clientSecret: string }> {
  const id = generateTenantId();
  const clientSecret = generateClientSecret();
  const hash = await hashClientSecret(clientSecret);
  const now = Math.floor(Date.now() / 1000);
  const record: TenantRecord = {
    schema_version: CURRENT_SCHEMA_VERSION,
    id,
    name: input.name,
    environment: input.environment,
    client_secret_hashes: [{ hash, created_at: now }],
    mtls: {
      cert_pem: input.cert_pem,
      key_pem: input.key_pem,
      cert_fingerprint_sha256: certFingerprintSha256(input.cert_pem),
      expires_at: certNotAfterUnix(input.cert_pem),
    },
    sealing_key_version: 1,
    created_at: now,
    updated_at: now,
  };
  return { record, clientSecret };
}

/** Apply a TenantPatch onto an existing record, bumping updated_at. */
export function applyPatch(current: TenantRecord, patch: TenantPatch): TenantRecord {
  return {
    ...current,
    name: patch.name ?? current.name,
    environment: patch.environment ?? current.environment,
    mtls:
      patch.cert_pem && patch.key_pem
        ? {
            cert_pem: patch.cert_pem,
            key_pem: patch.key_pem,
            cert_fingerprint_sha256: certFingerprintSha256(patch.cert_pem),
            expires_at: certNotAfterUnix(patch.cert_pem),
          }
        : current.mtls,
    updated_at: Math.floor(Date.now() / 1000),
  };
}

/**
 * Append a new client_secret hash, drop hashes older than
 * ROTATION_OVERLAP_SECONDS, cap at 2, and bump updated_at.
 * Returns the updated record alongside the new plaintext secret.
 */
export async function applyRotation(
  current: TenantRecord,
): Promise<{ record: TenantRecord; clientSecret: string }> {
  const clientSecret = generateClientSecret();
  const hash = await hashClientSecret(clientSecret);
  const now = Math.floor(Date.now() / 1000);
  const cutoff = now - ROTATION_OVERLAP_SECONDS;
  const record: TenantRecord = {
    ...current,
    client_secret_hashes: [
      { hash, created_at: now },
      ...current.client_secret_hashes.filter((h) => h.created_at >= cutoff),
    ].slice(0, 2),
    updated_at: now,
  };
  return { record, clientSecret };
}
