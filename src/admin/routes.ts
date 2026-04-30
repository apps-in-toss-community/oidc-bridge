import { Hono } from 'hono';
import type { TenantStore } from '../tenants/store.js';
import type { TenantRecord } from '../tenants/types.js';
import { isObject } from '../utils/json.js';
import { adminAuth } from './auth.js';

interface TenantBodyShape {
  name?: unknown;
  environment?: unknown;
  cert_pem?: unknown;
  key_pem?: unknown;
}

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
    const body = raw as TenantBodyShape;
    if (
      typeof body.name !== 'string' ||
      (body.environment !== 'production' && body.environment !== 'sandbox') ||
      typeof body.cert_pem !== 'string' ||
      typeof body.key_pem !== 'string'
    ) {
      return c.json({ error: 'invalid_request' }, 400);
    }
    const created = await store.create({
      name: body.name,
      environment: body.environment,
      cert_pem: body.cert_pem,
      key_pem: body.key_pem,
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
    const raw: unknown = await c.req.json().catch(() => ({}));
    if (!isObject(raw)) return c.json({ error: 'invalid_request' }, 400);
    const body = raw as TenantBodyShape;
    const patch: Parameters<TenantStore['update']>[1] = {};
    if (typeof body.name === 'string') patch.name = body.name;
    if (body.environment === 'production' || body.environment === 'sandbox') {
      patch.environment = body.environment;
    }
    if (typeof body.cert_pem === 'string') patch.cert_pem = body.cert_pem;
    if (typeof body.key_pem === 'string') patch.key_pem = body.key_pem;
    try {
      const updated = await store.update(c.req.param('id'), patch);
      return c.json(publicView(updated));
    } catch (e) {
      // store.update throws "tenant <id> not found" on unknown tenant
      if ((e as Error).message?.toLowerCase().includes('not found')) {
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
    const { client_secret } = await store.rotateSecret(c.req.param('id'));
    return c.json({ client_secret });
  });

  return r;
}
