import { mkdtempSync, readFileSync } from 'node:fs';
import { chmod, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { verifyClientSecret } from './crypto.js';
import { createFsStore } from './fs-store.js';
import type { TenantStore } from './store.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');

describe('fs-store', () => {
  let dataDir: string;
  let store: TenantStore;

  beforeEach(async () => {
    dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-test-'));
    store = await createFsStore(dataDir);
  });

  it('creates BRIDGE_DATA_DIR with mode 0700 if missing', async () => {
    const s = await stat(dataDir);
    expect(s.mode & 0o777).toBe(0o700);
  });

  it('refuses to start if BRIDGE_DATA_DIR has broader permissions', async () => {
    await chmod(dataDir, 0o755);
    await expect(createFsStore(dataDir)).rejects.toThrow(/permissions/);
  });

  it('writes .data-version on first run', async () => {
    const v = readFileSync(join(dataDir, '.data-version'), 'utf8');
    expect(v).toBe('1\n');
  });

  describe('create()', () => {
    it('returns plaintext client_secret once and stores only the bcrypt hash', async () => {
      const { tenant, client_secret } = await store.create({
        name: 'sdk-example',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      expect(tenant.id).toMatch(/^tnt_/);
      expect(client_secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(tenant.client_secret_hashes).toHaveLength(1);
      expect(tenant.client_secret_hashes[0]!.hash).toMatch(/^\$2[aby]\$12\$/);
      expect(await verifyClientSecret(client_secret, tenant.client_secret_hashes[0]!.hash)).toBe(
        true,
      );
    });

    it('writes the tenant file with mode 0600', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const s = await stat(join(dataDir, 'tenants', `${tenant.id}.json`));
      expect(s.mode & 0o777).toBe(0o600);
    });

    it('parses cert NotAfter into mtls.expires_at', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      expect(tenant.mtls.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });
  });

  describe('get()', () => {
    it('returns null for unknown tenant', async () => {
      expect(await store.get('tnt_nope')).toBeNull();
    });

    it('round-trips a created tenant', async () => {
      const { tenant: created } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const fetched = await store.get(created.id);
      expect(fetched).toEqual(created);
    });

    it('refuses path traversal via tenant_id', async () => {
      expect(await store.get('../etc/passwd')).toBeNull();
      expect(await store.get('tnt_/../passwd')).toBeNull();
    });
  });

  describe('list()', () => {
    it('returns TenantPublic entries with no secret material', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const list = await store.list();
      expect(list).toHaveLength(1);
      expect(list[0]).toMatchObject({
        id: tenant.id,
        name: 't',
        environment: 'sandbox',
      });
      expect(list[0]).not.toHaveProperty('client_secret_hashes');
      expect(list[0]).not.toHaveProperty('mtls');
      expect(list[0]!.mtls_fingerprint).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('rotateSecret()', () => {
    it('appends a new hash and keeps the previous one', async () => {
      const { tenant: t1, client_secret: s1 } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const { client_secret: s2 } = await store.rotateSecret(t1.id);
      const fetched = await store.get(t1.id);
      expect(fetched?.client_secret_hashes).toHaveLength(2);
      const hashes = fetched!.client_secret_hashes.map((h) => h.hash);
      expect(await verifyClientSecret(s1, hashes)).toBe(true);
      expect(await verifyClientSecret(s2, hashes)).toBe(true);
      expect(s1).not.toBe(s2);
    });
  });

  describe('update()', () => {
    it('updates name + environment + cert', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const updated = await store.update(tenant.id, { name: 'renamed', environment: 'production' });
      expect(updated.name).toBe('renamed');
      expect(updated.environment).toBe('production');
      expect(updated.updated_at).toBeGreaterThanOrEqual(tenant.updated_at);
    });
  });

  describe('delete()', () => {
    it('removes the tenant file', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      await store.delete(tenant.id);
      expect(await store.get(tenant.id)).toBeNull();
      const dir = await readdir(join(dataDir, 'tenants'));
      expect(dir.filter((f) => !f.startsWith('.'))).toEqual([]);
    });
  });

  describe('atomic write', () => {
    it('cleans up .tmp-* leftovers on startup', async () => {
      const { tenant } = await store.create({
        name: 't',
        environment: 'sandbox',
        cert_pem: certPem,
        key_pem: keyPem,
      });
      const fs = await import('node:fs/promises');
      await fs.writeFile(join(dataDir, 'tenants', '.tmp-stale-12345'), 'leftover');
      const reopened = await createFsStore(dataDir);
      expect(await reopened.get(tenant.id)).toBeTruthy();
      const dir = await readdir(join(dataDir, 'tenants'));
      expect(dir.filter((f) => f.startsWith('.tmp'))).toEqual([]);
    });
  });
});
