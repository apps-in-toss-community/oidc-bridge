import {
  certFingerprintSha256,
  certNotAfterUnix,
  generateClientSecret,
  generateTenantId,
  hashClientSecret,
} from './crypto.js';
import type { CreatedTenant, RotatedSecret, TenantStore } from './store.js';
import {
  CURRENT_SCHEMA_VERSION,
  type TenantCreateInput,
  type TenantPatch,
  type TenantPublic,
  type TenantRecord,
} from './types.js';

const TENANT_ID_PATTERN = /^tnt_[0-9a-hjkmnp-tv-z]{24}$/;
const SECRET_PREFIX = 'oidc-bridge-tenant-';
const ROTATION_OVERLAP_SECONDS = 72 * 3600;

function publicView(t: TenantRecord): TenantPublic {
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

export async function createGcpsmStore(projectId: string): Promise<TenantStore> {
  // Lazy import — only runs when this backend is selected.
  const mod = await import('@google-cloud/secret-manager');
  const client = new mod.SecretManagerServiceClient();
  const projectPath = client.projectPath(projectId);

  function secretName(id: string): string {
    return `projects/${projectId}/secrets/${SECRET_PREFIX}${id}`;
  }

  async function readSecret(id: string): Promise<TenantRecord | null> {
    try {
      const [result] = await client.accessSecretVersion({
        name: `${secretName(id)}/versions/latest`,
      });
      const data = result.payload?.data;
      if (!data) return null;
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(data as Uint8Array);
      return JSON.parse(buf.toString('utf8')) as TenantRecord;
    } catch (err: unknown) {
      if ((err as { code?: number }).code === 5) return null; // NOT_FOUND
      throw err;
    }
  }

  async function writeSecret(id: string, record: TenantRecord, isCreate: boolean): Promise<void> {
    const secretId = `${SECRET_PREFIX}${id}`;
    const payload = Buffer.from(JSON.stringify(record), 'utf8');
    if (isCreate) {
      await client.createSecret({
        parent: projectPath,
        secretId,
        secret: {
          replication: { automatic: {} },
          labels: { app: 'oidc-bridge', tenant_id: id },
        },
      });
    }
    await client.addSecretVersion({ parent: secretName(id), payload: { data: payload } });
  }

  async function get(id: string): Promise<TenantRecord | null> {
    if (!TENANT_ID_PATTERN.test(id)) return null;
    const record = await readSecret(id);
    if (record && record.schema_version > CURRENT_SCHEMA_VERSION) {
      throw new Error(
        `tenant ${id} has schema_version ${record.schema_version} > ${CURRENT_SCHEMA_VERSION}`,
      );
    }
    return record;
  }

  async function list(): Promise<TenantPublic[]> {
    const out: TenantPublic[] = [];
    for await (const s of client.listSecretsAsync({
      parent: projectPath,
      filter: `name:${SECRET_PREFIX}`,
    })) {
      const name = (s as { name?: string }).name;
      if (!name) continue;
      const id = name.substring(name.indexOf(SECRET_PREFIX) + SECRET_PREFIX.length);
      const t = await get(id);
      if (t) out.push(publicView(t));
    }
    return out;
  }

  async function create(input: TenantCreateInput): Promise<CreatedTenant> {
    const id = generateTenantId();
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    const now = Math.floor(Date.now() / 1000);
    const tenant: TenantRecord = {
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
    await writeSecret(id, tenant, true);
    return { tenant, client_secret: secret };
  }

  async function update(id: string, patch: TenantPatch): Promise<TenantRecord> {
    const current = await get(id);
    if (!current) throw new Error(`tenant ${id} not found`);
    const next: TenantRecord = {
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
    await writeSecret(id, next, false);
    return next;
  }

  async function rotateSecret(id: string): Promise<RotatedSecret> {
    const current = await get(id);
    if (!current) throw new Error(`tenant ${id} not found`);
    const secret = generateClientSecret();
    const hash = await hashClientSecret(secret);
    const now = Math.floor(Date.now() / 1000);
    const cutoff = now - ROTATION_OVERLAP_SECONDS;
    const next: TenantRecord = {
      ...current,
      client_secret_hashes: [
        { hash, created_at: now },
        ...current.client_secret_hashes.filter((h) => h.created_at >= cutoff),
      ].slice(0, 2),
      updated_at: now,
    };
    await writeSecret(id, next, false);
    return { client_secret: secret };
  }

  async function deleteTenant(id: string): Promise<void> {
    if (!TENANT_ID_PATTERN.test(id)) return;
    try {
      await client.deleteSecret({ name: secretName(id) });
    } catch (err: unknown) {
      if ((err as { code?: number }).code !== 5) throw err;
    }
  }

  return { get, list, create, update, rotateSecret, delete: deleteTenant };
}
