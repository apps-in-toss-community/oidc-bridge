import { randomBytes } from 'node:crypto';
import {
  chmod,
  mkdir,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
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
const ROTATION_OVERLAP_SECONDS = 72 * 3600;

function tenantPath(dataDir: string, id: string): string {
  return join(dataDir, 'tenants', `${id}.json`);
}

async function ensureDirAt(path: string, mode: number): Promise<void> {
  await mkdir(path, { recursive: true, mode });
  // mkdir's `mode` is masked by umask on existing dirs; chmod to be exact.
  await chmod(path, mode);
}

async function checkPerm(path: string, expected: number): Promise<void> {
  const s = await stat(path);
  const actual = s.mode & 0o777;
  if (actual !== expected) {
    throw new Error(
      `refusing to start: ${path} has permissions ${actual.toString(8)} (expected ${expected.toString(8)})`,
    );
  }
}

async function atomicWriteJson<T>(path: string, value: T): Promise<void> {
  const dir = path.substring(0, path.lastIndexOf('/'));
  const tmp = join(dir, `.tmp-${randomBytes(8).toString('hex')}`);
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  await rename(tmp, path);
}

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

export async function createFsStore(dataDir: string): Promise<TenantStore> {
  // Check permissions before ensureDirAt re-chmodds if dir already exists.
  try {
    await checkPerm(dataDir, 0o700);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      // Dir doesn't exist yet — ensureDirAt will create it with 0700.
    } else {
      throw err;
    }
  }
  await ensureDirAt(dataDir, 0o700);
  const tenantsDir = join(dataDir, 'tenants');
  await ensureDirAt(tenantsDir, 0o700);

  // .data-version gate
  const versionPath = join(dataDir, '.data-version');
  try {
    const v = (await readFile(versionPath, 'utf8')).trim();
    if (v !== String(CURRENT_SCHEMA_VERSION)) {
      throw new Error(
        `refusing to start: .data-version is ${v}, bridge supports ${CURRENT_SCHEMA_VERSION}`,
      );
    }
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      await writeFile(versionPath, `${CURRENT_SCHEMA_VERSION}\n`, { mode: 0o600 });
    } else {
      throw err;
    }
  }

  // Sweep .tmp-* leftovers from prior crashes.
  for (const entry of await readdir(tenantsDir)) {
    if (entry.startsWith('.tmp-')) {
      await unlink(join(tenantsDir, entry));
    }
  }

  async function get(id: string): Promise<TenantRecord | null> {
    if (!TENANT_ID_PATTERN.test(id)) return null;
    try {
      const raw = await readFile(tenantPath(dataDir, id), 'utf8');
      const parsed: TenantRecord = JSON.parse(raw);
      if (parsed.schema_version > CURRENT_SCHEMA_VERSION) {
        throw new Error(
          `tenant ${id} has schema_version ${parsed.schema_version} > ${CURRENT_SCHEMA_VERSION}`,
        );
      }
      return parsed;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
  }

  async function list(): Promise<TenantPublic[]> {
    const entries = await readdir(tenantsDir);
    const out: TenantPublic[] = [];
    for (const entry of entries) {
      if (!entry.endsWith('.json') || entry.startsWith('.')) continue;
      const id = entry.replace(/\.json$/, '');
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
    await atomicWriteJson(tenantPath(dataDir, id), tenant);
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
    await atomicWriteJson(tenantPath(dataDir, id), next);
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
    await atomicWriteJson(tenantPath(dataDir, id), next);
    return { client_secret: secret };
  }

  async function deleteTenant(id: string): Promise<void> {
    if (!TENANT_ID_PATTERN.test(id)) return;
    await rm(tenantPath(dataDir, id), { force: true });
  }

  return { get, list, create, update, rotateSecret, delete: deleteTenant };
}
