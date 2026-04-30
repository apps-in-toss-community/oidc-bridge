import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { verifyClientSecret } from './crypto.js';
import {
  applyPatch,
  applyRotation,
  buildNewTenantRecord,
  ROTATION_OVERLAP_SECONDS,
  TENANT_ID_PATTERN,
} from './record.js';
import type { TenantRecord } from './types.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

const baseInput = {
  name: 'test-tenant',
  environment: 'sandbox' as const,
  cert_pem: certPem,
  key_pem: keyPem,
};

describe('buildNewTenantRecord', () => {
  it('produces a valid tenant id matching TENANT_ID_PATTERN', async () => {
    const { record } = await buildNewTenantRecord(baseInput);
    expect(record.id).toMatch(TENANT_ID_PATTERN);
  });

  it('produces a base64url client secret of 43 chars', async () => {
    const { clientSecret } = await buildNewTenantRecord(baseInput);
    expect(clientSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('stores one bcrypt hash that verifies against the returned secret', async () => {
    const { record, clientSecret } = await buildNewTenantRecord(baseInput);
    expect(record.client_secret_hashes).toHaveLength(1);
    expect(record.client_secret_hashes[0]!.hash).toMatch(/^\$2[aby]\$12\$/);
    expect(await verifyClientSecret(clientSecret, record.client_secret_hashes[0]!.hash)).toBe(true);
  });

  it('sets schema_version to 1', async () => {
    const { record } = await buildNewTenantRecord(baseInput);
    expect(record.schema_version).toBe(1);
  });

  it('populates mtls fingerprint and expiry from the cert', async () => {
    const { record } = await buildNewTenantRecord(baseInput);
    expect(record.mtls.cert_fingerprint_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(record.mtls.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('sets sealing_key_version to 1', async () => {
    const { record } = await buildNewTenantRecord(baseInput);
    expect(record.sealing_key_version).toBe(1);
  });

  it('sets created_at and updated_at to current unix seconds', async () => {
    const before = Math.floor(Date.now() / 1000);
    const { record } = await buildNewTenantRecord(baseInput);
    const after = Math.floor(Date.now() / 1000);
    expect(record.created_at).toBeGreaterThanOrEqual(before);
    expect(record.created_at).toBeLessThanOrEqual(after);
    expect(record.updated_at).toBe(record.created_at);
  });
});

describe('applyPatch', () => {
  async function makeRecord(): Promise<TenantRecord> {
    const { record } = await buildNewTenantRecord(baseInput);
    return record;
  }

  it('updates name', async () => {
    const current = await makeRecord();
    const next = applyPatch(current, { name: 'renamed' });
    expect(next.name).toBe('renamed');
  });

  it('updates environment', async () => {
    const current = await makeRecord();
    const next = applyPatch(current, { environment: 'production' });
    expect(next.environment).toBe('production');
  });

  it('bumps updated_at', async () => {
    const current = await makeRecord();
    const before = Math.floor(Date.now() / 1000);
    const next = applyPatch(current, { name: 'x' });
    expect(next.updated_at).toBeGreaterThanOrEqual(before);
    expect(next.updated_at).toBeGreaterThanOrEqual(current.updated_at);
  });

  it('replaces mtls when both cert_pem and key_pem are provided', async () => {
    const current = await makeRecord();
    const oldFingerprint = current.mtls.cert_fingerprint_sha256;
    const next = applyPatch(current, { cert_pem: certPem, key_pem: keyPem });
    // Same cert → same fingerprint, but mtls block was rebuilt
    expect(next.mtls.cert_fingerprint_sha256).toBe(oldFingerprint);
    expect(next.mtls.cert_pem).toBe(certPem);
  });

  it('preserves mtls when cert_pem/key_pem are absent', async () => {
    const current = await makeRecord();
    const next = applyPatch(current, { name: 'no-cert-change' });
    expect(next.mtls).toBe(current.mtls);
  });

  it('preserves client_secret_hashes unchanged', async () => {
    const current = await makeRecord();
    const next = applyPatch(current, { name: 'y' });
    expect(next.client_secret_hashes).toEqual(current.client_secret_hashes);
  });
});

describe('applyRotation', () => {
  async function makeRecord(): Promise<TenantRecord> {
    const { record } = await buildNewTenantRecord(baseInput);
    return record;
  }

  it('appends a new hash as the first entry', async () => {
    const current = await makeRecord();
    const oldHash = current.client_secret_hashes[0]!.hash;
    const { record: next, clientSecret } = await applyRotation(current);
    expect(next.client_secret_hashes).toHaveLength(2);
    expect(next.client_secret_hashes[0]!.hash).not.toBe(oldHash);
    expect(await verifyClientSecret(clientSecret, next.client_secret_hashes[0]!.hash)).toBe(true);
  });

  it('keeps the previous hash so both secrets verify during overlap', async () => {
    const { record: initial, clientSecret: s1 } = await buildNewTenantRecord(baseInput);
    const { record: rotated, clientSecret: s2 } = await applyRotation(initial);
    const hashes = rotated.client_secret_hashes.map((h) => h.hash);
    expect(await verifyClientSecret(s1, hashes)).toBe(true);
    expect(await verifyClientSecret(s2, hashes)).toBe(true);
  });

  it('drops expired hashes older than ROTATION_OVERLAP_SECONDS', async () => {
    const { record: initial } = await buildNewTenantRecord(baseInput);
    // Backdate the existing hash so it falls outside the overlap window.
    const stale: TenantRecord = {
      ...initial,
      client_secret_hashes: [
        {
          hash: initial.client_secret_hashes[0]!.hash,
          created_at: Math.floor(Date.now() / 1000) - ROTATION_OVERLAP_SECONDS - 1,
        },
      ],
    };
    const { record: next } = await applyRotation(stale);
    // Expired hash should be dropped; only the new hash remains.
    expect(next.client_secret_hashes).toHaveLength(1);
  });

  it('caps client_secret_hashes at 2', async () => {
    // Build a record that already has 2 fresh hashes (manual state).
    const now = Math.floor(Date.now() / 1000);
    const { record: initial } = await buildNewTenantRecord(baseInput);
    const stuffed: TenantRecord = {
      ...initial,
      client_secret_hashes: [
        { hash: initial.client_secret_hashes[0]!.hash, created_at: now },
        { hash: initial.client_secret_hashes[0]!.hash, created_at: now - 1 },
      ],
    };
    const { record: next } = await applyRotation(stuffed);
    expect(next.client_secret_hashes).toHaveLength(2);
  });

  it('bumps updated_at', async () => {
    const current = await makeRecord();
    const before = Math.floor(Date.now() / 1000);
    const { record: next } = await applyRotation(current);
    expect(next.updated_at).toBeGreaterThanOrEqual(before);
  });
});
