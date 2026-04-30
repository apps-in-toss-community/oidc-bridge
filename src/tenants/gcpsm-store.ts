import {
  applyPatch,
  applyRotation,
  buildNewTenantRecord,
  publicView,
  TENANT_ID_PATTERN,
} from './record.js';
import type { CreatedTenant, RotatedSecret, TenantStore } from './store.js';
import { TenantNotFoundError } from './store.js';
import {
  CURRENT_SCHEMA_VERSION,
  type TenantCreateInput,
  type TenantPatch,
  type TenantRecord,
} from './types.js';

const SECRET_PREFIX = 'oidc-bridge-tenant-';

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

  async function list() {
    const out = [];
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
    const { record: tenant, clientSecret: client_secret } = await buildNewTenantRecord(input);
    await writeSecret(tenant.id, tenant, true);
    return { tenant, client_secret };
  }

  async function update(id: string, patch: TenantPatch): Promise<TenantRecord> {
    const current = await get(id);
    if (!current) throw new TenantNotFoundError(id);
    const next = applyPatch(current, patch);
    await writeSecret(id, next, false);
    return next;
  }

  async function rotateSecret(id: string): Promise<RotatedSecret> {
    const current = await get(id);
    if (!current) throw new TenantNotFoundError(id);
    const { record: next, clientSecret: client_secret } = await applyRotation(current);
    await writeSecret(id, next, false);
    return { client_secret };
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
