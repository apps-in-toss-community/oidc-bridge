import { Hono } from 'hono';
import type { TenantStore } from '../tenants/store.js';
import { TenantNotFoundError } from '../tenants/store.js';
import type { TenantRecord } from '../tenants/types.js';
import { isObject } from '../utils/json.js';
import { adminAuth } from './auth.js';

function publicView(t: TenantRecord) {
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

export function buildAdminRouter(store: TenantStore, adminToken: string): Hono {
  const r = new Hono();
  r.use('*', adminAuth(adminToken));

  r.get('/tenants', async (c) => c.json({ tenants: await store.list() }));

  r.post('/tenants', async (c) => {
    const raw: unknown = await c.req.json().catch(() => ({}));
    if (!isObject(raw)) return c.json({ error: 'invalid_request' }, 400);
    if (
      typeof raw.name !== 'string' ||
      (raw.environment !== 'production' && raw.environment !== 'sandbox') ||
      typeof raw.cert_pem !== 'string' ||
      typeof raw.key_pem !== 'string'
    ) {
      return c.json({ error: 'invalid_request' }, 400);
    }
    const created = await store.create({
      name: raw.name,
      environment: raw.environment,
      cert_pem: raw.cert_pem,
      key_pem: raw.key_pem,
    });
    return c.json(
      {
        tenant: publicView(created.tenant),
        client_id: created.tenant.id,
        client_secret: created.client_secret,
      },
      201,
    );
  });

  r.get('/tenants/:id', async (c) => {
    const t = await store.get(c.req.param('id'));
    if (!t) return c.json({ error: 'not_found' }, 404);
    return c.json(publicView(t));
  });

  r.patch('/tenants/:id', async (c) => {
    const id = c.req.param('id');
    const raw: unknown = await c.req.json().catch(() => ({}));
    if (!isObject(raw)) return c.json({ error: 'invalid_request' }, 400);
    // Reject half-pair PEM updates: both cert_pem and key_pem must be supplied together.
    const hasCert = typeof raw.cert_pem === 'string';
    const hasKey = typeof raw.key_pem === 'string';
    if (hasCert !== hasKey) {
      return c.json({ error: 'invalid_request' }, 400);
    }
    const patch: Parameters<TenantStore['update']>[1] = {};
    if (typeof raw.name === 'string') patch.name = raw.name;
    if (raw.environment === 'production' || raw.environment === 'sandbox') {
      patch.environment = raw.environment;
    }
    if (hasCert && hasKey) {
      patch.cert_pem = raw.cert_pem as string;
      patch.key_pem = raw.key_pem as string;
    }
    try {
      const updated = await store.update(id, patch);
      return c.json(publicView(updated));
    } catch (e) {
      if (e instanceof TenantNotFoundError) {
        return c.json({ error: 'not_found' }, 404);
      }
      throw e;
    }
  });

  r.delete('/tenants/:id', async (c) => {
    await store.delete(c.req.param('id'));
    return c.body(null, 204);
  });

  r.post('/tenants/:id/secrets/rotate', async (c) => {
    const id = c.req.param('id');
    try {
      const { client_secret } = await store.rotateSecret(id);
      return c.json({ client_secret });
    } catch (e) {
      if (e instanceof TenantNotFoundError) {
        return c.json({ error: 'not_found' }, 404);
      }
      throw e;
    }
  });

  return r;
}
