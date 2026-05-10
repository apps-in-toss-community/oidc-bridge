import type { Context, Hono } from 'hono';
import { z } from 'zod';
import type { MasterKeyProvider } from '../master-keys/index.js';
import type { ApiToken, AppRecord, Workspace } from '../storage/types.js';
import { adminAuth } from './auth.js';
import type { Stage } from './ownership.js';
import { ConflictError, NotFoundError, type Service, type ServiceCtx } from './service.js';

export interface MountAdminRoutesOptions {
  service: Service;
  masterKeyProvider: MasterKeyProvider;
  activeMasterKeyVersion: () => number;
  stage: () => Stage;
  onUnexpectedError?: (err: unknown) => void;
}

const CreateWorkspaceSchema = z.object({ name: z.string().min(1) });
const UpdateWorkspaceSchema = z.object({ name: z.string().min(1).optional() });
const CreateAppSchema = z.object({
  workspaceId: z.string().min(1),
  appIdToss: z.string().min(1),
  displayTitle: z.string().min(1),
  mtlsCertPem: z.string().min(1),
  mtlsKeyPem: z.string().min(1),
  allowedOrigins: z.array(z.url()).default([]),
});
const UpdateAppSchema = z.object({
  displayTitle: z.string().min(1).optional(),
  allowedOrigins: z.array(z.url()).optional(),
});
const ToggleRawTokensSchema = z.object({ enabled: z.boolean() });
const CreateApiTokenSchema = z.object({
  name: z.string().min(1),
  scopes: z.array(z.string()).default([]),
});

function workspaceJson(w: Workspace) {
  return {
    id: w.id,
    ownerUserId: w.ownerUserId,
    name: w.name,
    createdAt: w.createdAt.toISOString(),
  };
}

function appJson(a: AppRecord) {
  return {
    id: a.id,
    workspaceId: a.workspaceId,
    appIdToss: a.appIdToss,
    displayTitle: a.displayTitle,
    clientId: a.clientId,
    allowedOrigins: a.allowedOrigins,
    ownershipStatus: a.ownershipStatus,
    ownershipGraceUntil: a.ownershipGraceUntil?.toISOString() ?? null,
    rawTokensEnabled: a.rawTokensEnabled,
    sealingKeyVersion: a.sealingKeyVersion,
    mtlsPresent: true,
    createdAt: a.createdAt.toISOString(),
    updatedAt: a.updatedAt.toISOString(),
  };
}

function apiTokenJson(t: ApiToken) {
  return {
    id: t.id,
    name: t.name,
    scopes: t.scopes,
    createdAt: t.createdAt.toISOString(),
    lastUsedAt: t.lastUsedAt?.toISOString() ?? null,
  };
}

function ctxFromHono(c: Context): ServiceCtx {
  const user = c.get('user');
  return { actorUserId: user.id };
}

function handleError(err: unknown, onUnexpectedError?: (err: unknown) => void) {
  if (err instanceof NotFoundError) {
    return Response.json({ error: 'not_found', error_description: err.message }, { status: 404 });
  }
  if (err instanceof ConflictError) {
    return Response.json({ error: 'conflict', error_description: err.message }, { status: 409 });
  }
  if (onUnexpectedError) onUnexpectedError(err);
  else console.error('admin route error', err);
  return Response.json(
    { error: 'server_error', error_description: 'unexpected error' },
    { status: 500 },
  );
}

// Routes under `/admin/*` that authenticate with their own scheme (e.g. cookie
// session) instead of the API_TOKEN bearer. These must be exempt from
// `adminAuth` so a user can sign in without already holding an admin bearer.
const PUBLIC_ADMIN_PATHS: ReadonlySet<string> = new Set(['/admin/login', '/admin/logout']);

export function mountAdminRoutes(app: Hono, opts: MountAdminRoutesOptions): void {
  const auth = adminAuth({ service: opts.service, requireScope: 'admin' });
  app.use('/admin/*', async (c, next) => {
    if (PUBLIC_ADMIN_PATHS.has(c.req.path)) return next();
    return auth(c, next);
  });

  app.post('/admin/workspaces', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = CreateWorkspaceSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const w = await opts.service.workspaces.create(ctxFromHono(c), parsed.data);
      return c.json(workspaceJson(w), 201);
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.get('/admin/workspaces', async (c) => {
    const list = await opts.service.workspaces.list(ctxFromHono(c));
    return c.json(list.map(workspaceJson));
  });

  app.get('/admin/workspaces/:id', async (c) => {
    try {
      const w = await opts.service.workspaces.get(ctxFromHono(c), c.req.param('id'));
      return c.json(workspaceJson(w));
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.patch('/admin/workspaces/:id', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = UpdateWorkspaceSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const w = await opts.service.workspaces.update(
        ctxFromHono(c),
        c.req.param('id'),
        parsed.data,
      );
      return c.json(workspaceJson(w));
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.delete('/admin/workspaces/:id', async (c) => {
    try {
      await opts.service.workspaces.delete(ctxFromHono(c), c.req.param('id'));
      return c.body(null, 204);
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.post('/admin/workspaces/:wsId/apps', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = CreateAppSchema.safeParse({ ...json, workspaceId: c.req.param('wsId') });
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const version = opts.activeMasterKeyVersion();
      const masterKey = await opts.masterKeyProvider.getKeyBytes(version);
      const result = await opts.service.apps.create(ctxFromHono(c), {
        workspaceId: parsed.data.workspaceId,
        appIdToss: parsed.data.appIdToss,
        displayTitle: parsed.data.displayTitle,
        mtlsCert: new TextEncoder().encode(parsed.data.mtlsCertPem),
        mtlsKey: new TextEncoder().encode(parsed.data.mtlsKeyPem),
        allowedOrigins: parsed.data.allowedOrigins,
        sealingKeyVersion: version,
        masterKey,
        stage: opts.stage(),
      });
      return c.json(
        {
          app: appJson(result.app),
          clientId: result.clientId,
          clientSecret: result.clientSecret,
        },
        201,
      );
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.get('/admin/workspaces/:wsId/apps', async (c) => {
    try {
      const list = await opts.service.apps.list(ctxFromHono(c), c.req.param('wsId'));
      return c.json(list.map(appJson));
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.get('/admin/apps/:id', async (c) => {
    try {
      const a = await opts.service.apps.get(ctxFromHono(c), c.req.param('id'));
      return c.json(appJson(a));
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.patch('/admin/apps/:id', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = UpdateAppSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const a = await opts.service.apps.update(ctxFromHono(c), c.req.param('id'), parsed.data);
      return c.json(appJson(a));
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.delete('/admin/apps/:id', async (c) => {
    try {
      await opts.service.apps.delete(ctxFromHono(c), c.req.param('id'));
      return c.body(null, 204);
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.post('/admin/apps/:id/secrets/rotate', async (c) => {
    try {
      const r = await opts.service.apps.rotateSecret(ctxFromHono(c), c.req.param('id'));
      return c.json({ app: appJson(r.app), clientSecret: r.clientSecret });
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.post('/admin/apps/:id/raw-tokens', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = ToggleRawTokensSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const a = await opts.service.apps.toggleRawTokens(
        ctxFromHono(c),
        c.req.param('id'),
        parsed.data.enabled,
      );
      return c.json(appJson(a));
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.post('/admin/api-tokens', async (c) => {
    const json = await c.req.json().catch(() => ({}));
    const parsed = CreateApiTokenSchema.safeParse(json);
    if (!parsed.success) {
      return c.json({ error: 'invalid_request', error_description: parsed.error.message }, 400);
    }
    try {
      const r = await opts.service.apiTokens.create(ctxFromHono(c), parsed.data);
      return c.json({ token: apiTokenJson(r.token), plaintext: r.plaintext }, 201);
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });

  app.get('/admin/api-tokens', async (c) => {
    const list = await opts.service.apiTokens.list(ctxFromHono(c));
    return c.json(list.map(apiTokenJson));
  });

  app.delete('/admin/api-tokens/:id', async (c) => {
    try {
      await opts.service.apiTokens.delete(ctxFromHono(c), c.req.param('id'));
      return c.body(null, 204);
    } catch (err) {
      return handleError(err, opts.onUnexpectedError);
    }
  });
}
