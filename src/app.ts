import { Hono } from 'hono';
import { type MountAdminRoutesOptions, mountAdminRoutes } from './apps/routes.js';

export interface CreateAppOptions {
  admin?: MountAdminRoutesOptions;
}

/**
 * Build the Hono app.
 *
 * Factory rather than module-level singleton so tests can construct
 * fresh instances and so server.ts stays a thin entrypoint.
 */
export function createApp(opts: CreateAppOptions = {}): Hono {
  const app = new Hono();
  app.get('/healthz', (c) => c.json({ status: 'ok' }));
  if (opts.admin) {
    mountAdminRoutes(app, opts.admin);
  }
  return app;
}
