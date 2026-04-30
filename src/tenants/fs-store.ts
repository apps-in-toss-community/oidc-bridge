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

  async function list() {
    const entries = await readdir(tenantsDir);
    const out = [];
    for (const entry of entries) {
      if (!entry.endsWith('.json') || entry.startsWith('.')) continue;
      const id = entry.replace(/\.json$/, '');
      const t = await get(id);
      if (t) out.push(publicView(t));
    }
    return out;
  }

  async function create(input: TenantCreateInput): Promise<CreatedTenant> {
    const { record: tenant, clientSecret: client_secret } = await buildNewTenantRecord(input);
    await atomicWriteJson(tenantPath(dataDir, tenant.id), tenant);
    return { tenant, client_secret };
  }

  async function update(id: string, patch: TenantPatch): Promise<TenantRecord> {
    const current = await get(id);
    if (!current) throw new TenantNotFoundError(id);
    const next = applyPatch(current, patch);
    await atomicWriteJson(tenantPath(dataDir, id), next);
    return next;
  }

  async function rotateSecret(id: string): Promise<RotatedSecret> {
    const current = await get(id);
    if (!current) throw new TenantNotFoundError(id);
    const { record: next, clientSecret: client_secret } = await applyRotation(current);
    await atomicWriteJson(tenantPath(dataDir, id), next);
    return { client_secret };
  }

  async function deleteTenant(id: string): Promise<void> {
    if (!TENANT_ID_PATTERN.test(id)) return;
    await rm(tenantPath(dataDir, id), { force: true });
  }

  return { get, list, create, update, rotateSecret, delete: deleteTenant };
}
