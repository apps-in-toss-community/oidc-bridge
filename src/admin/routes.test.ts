import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { createFsStore } from '../tenants/fs-store.js';
import type { TenantStore } from '../tenants/store.js';
import type { TenantPublic } from '../tenants/types.js';
import { buildAdminRouter } from './routes.js';

const certPem = readFileSync('src/__fixtures__/test-mtls.cert.pem', 'utf8');
const keyPem = readFileSync('src/__fixtures__/test-mtls.key.pem', 'utf8');
const ADMIN = 'admin-token';

async function setup(): Promise<{ app: Hono; store: TenantStore }> {
  const dataDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-admin-test-'));
  const store = await createFsStore(dataDir);
  const app = new Hono();
  app.route('/admin', buildAdminRouter(store, ADMIN));
  return { app, store };
}

const authHeader = { authorization: `Bearer ${ADMIN}` };

const validCreateBody = {
  name: 'test-tenant',
  environment: 'sandbox',
  cert_pem: certPem,
  key_pem: keyPem,
};

interface CreateResponse {
  client_id: string;
  client_secret: string;
  tenant: TenantPublic;
}

interface ListResponse {
  tenants: TenantPublic[];
}

interface RotateResponse {
  client_secret: string;
}

interface ErrorResponse {
  error: string;
}

async function jsonAs<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

describe('/admin/tenants CRUD', () => {
  describe('authentication', () => {
    it('rejects without Authorization header', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants');
      expect(res.status).toBe(401);
    });

    it('rejects with wrong token', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', {
        headers: { authorization: 'Bearer wrong' },
      });
      expect(res.status).toBe(401);
    });
  });

  describe('POST /admin/tenants', () => {
    it('creates tenant and returns client_id, client_secret, and tenant public view', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify(validCreateBody),
      });
      expect(res.status).toBe(201);
      const body = await jsonAs<CreateResponse>(res);
      expect(typeof body.client_id).toBe('string');
      expect(body.client_id).toMatch(/^tnt_/);
      expect(typeof body.client_secret).toBe('string');
      expect(body.client_secret.length).toBeGreaterThan(0);
      expect(body.tenant).toMatchObject({
        id: body.client_id,
        name: 'test-tenant',
        environment: 'sandbox',
      });
      // must NOT expose mtls private key or secret hashes
      expect((body.tenant as unknown as Record<string, unknown>).mtls).toBeUndefined();
      expect(
        (body.tenant as unknown as Record<string, unknown>).client_secret_hashes,
      ).toBeUndefined();
    });

    it('returns 400 when name is missing', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify({ environment: 'sandbox', cert_pem: certPem, key_pem: keyPem }),
      });
      expect(res.status).toBe(400);
      const body = await jsonAs<ErrorResponse>(res);
      expect(body).toMatchObject({ error: 'invalid_request' });
    });

    it('returns 400 when environment is invalid', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify({
          name: 'x',
          environment: 'staging',
          cert_pem: certPem,
          key_pem: keyPem,
        }),
      });
      expect(res.status).toBe(400);
    });

    it('returns 400 when cert_pem is missing', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'x', environment: 'sandbox', key_pem: keyPem }),
      });
      expect(res.status).toBe(400);
    });

    it('returns 400 when body is not an object', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: '"not-an-object"',
      });
      expect(res.status).toBe(400);
    });
  });

  describe('GET /admin/tenants', () => {
    it('returns empty list when no tenants', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants', { headers: authHeader });
      expect(res.status).toBe(200);
      const body = await jsonAs<ListResponse>(res);
      expect(body).toEqual({ tenants: [] });
    });

    it('returns list with created tenants (no secret material)', async () => {
      const { app } = await setup();
      // create one
      await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify(validCreateBody),
      });
      const res = await app.request('/admin/tenants', { headers: authHeader });
      expect(res.status).toBe(200);
      const body = await jsonAs<ListResponse>(res);
      expect(Array.isArray(body.tenants)).toBe(true);
      expect(body.tenants).toHaveLength(1);
      const t = body.tenants[0] as unknown as Record<string, unknown>;
      expect(t).toHaveProperty('id');
      expect(t).toHaveProperty('name', 'test-tenant');
      expect(t).not.toHaveProperty('mtls');
      expect(t).not.toHaveProperty('client_secret_hashes');
    });
  });

  describe('GET /admin/tenants/:id', () => {
    it('returns the tenant public view', async () => {
      const { app } = await setup();
      const createRes = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify(validCreateBody),
      });
      const { client_id } = await jsonAs<CreateResponse>(createRes);
      const res = await app.request(`/admin/tenants/${client_id}`, { headers: authHeader });
      expect(res.status).toBe(200);
      const body = await jsonAs<TenantPublic>(res);
      expect(body).toMatchObject({ id: client_id, name: 'test-tenant', environment: 'sandbox' });
      expect((body as unknown as Record<string, unknown>).client_secret_hashes).toBeUndefined();
    });

    it('returns 404 for unknown tenant id', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants/tnt_nonexistent12345678901234', {
        headers: authHeader,
      });
      expect(res.status).toBe(404);
      const body = await jsonAs<ErrorResponse>(res);
      expect(body).toMatchObject({ error: 'not_found' });
    });
  });

  describe('PATCH /admin/tenants/:id', () => {
    it('updates name and returns public view', async () => {
      const { app } = await setup();
      const createRes = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify(validCreateBody),
      });
      const { client_id } = await jsonAs<CreateResponse>(createRes);
      const res = await app.request(`/admin/tenants/${client_id}`, {
        method: 'PATCH',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'updated-name' }),
      });
      expect(res.status).toBe(200);
      const body = await jsonAs<TenantPublic>(res);
      expect(body).toMatchObject({ id: client_id, name: 'updated-name' });
    });

    it('returns 404 for unknown tenant', async () => {
      const { app } = await setup();
      const res = await app.request('/admin/tenants/tnt_nonexistent12345678901234', {
        method: 'PATCH',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'x' }),
      });
      expect(res.status).toBe(404);
    });
  });

  describe('DELETE /admin/tenants/:id', () => {
    it('returns 204 and removes tenant', async () => {
      const { app } = await setup();
      const createRes = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify(validCreateBody),
      });
      const { client_id } = await jsonAs<CreateResponse>(createRes);
      const deleteRes = await app.request(`/admin/tenants/${client_id}`, {
        method: 'DELETE',
        headers: authHeader,
      });
      expect(deleteRes.status).toBe(204);
      // verify it's gone
      const getRes = await app.request(`/admin/tenants/${client_id}`, { headers: authHeader });
      expect(getRes.status).toBe(404);
    });
  });

  describe('POST /admin/tenants/:id/secrets/rotate', () => {
    it('returns a new client_secret', async () => {
      const { app } = await setup();
      const createRes = await app.request('/admin/tenants', {
        method: 'POST',
        headers: { ...authHeader, 'content-type': 'application/json' },
        body: JSON.stringify(validCreateBody),
      });
      const { client_id, client_secret: originalSecret } = await jsonAs<CreateResponse>(createRes);
      const rotateRes = await app.request(`/admin/tenants/${client_id}/secrets/rotate`, {
        method: 'POST',
        headers: authHeader,
      });
      expect(rotateRes.status).toBe(200);
      const body = await jsonAs<RotateResponse>(rotateRes);
      expect(typeof body.client_secret).toBe('string');
      expect(body.client_secret.length).toBeGreaterThan(0);
      expect(body.client_secret).not.toBe(originalSecret);
    });
  });
});
