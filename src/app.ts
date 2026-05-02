import { Hono } from 'hono';
import { type MountAdminRoutesOptions, mountAdminRoutes } from './apps/routes.js';
import type { OidcConfig } from './config.js';
import { discoveryRoute } from './oidc/discovery-route.js';
import { jwksRoute } from './oidc/jwks-route.js';
import type { SigningKeyRegistry } from './oidc/signing-keys.js';

export interface CreateAppOptions {
  admin?: MountAdminRoutesOptions;
  oidc?: {
    config: OidcConfig;
    signingKeyRegistry: SigningKeyRegistry;
  };
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
  if (opts.oidc) {
    app.route('/', discoveryRoute({ issuer: opts.oidc.config.issuer }));
    app.route('/', jwksRoute({ registry: opts.oidc.signingKeyRegistry }));
  }
  return app;
}
