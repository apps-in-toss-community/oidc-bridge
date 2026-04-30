import { Hono } from 'hono';
import { buildAdminRouter } from './admin/routes.js';
import type { Config } from './config.js';
import { mountDiscovery } from './oidc/discovery.js';
import { mountJwks } from './oidc/jwks.js';
import { mountRevoke } from './oidc/revoke.js';
import { mountToken } from './oidc/token.js';
import { mountUserinfo } from './oidc/userinfo.js';
import type { TenantStore } from './tenants/store.js';

export interface AppDeps {
  config: Config;
  store: TenantStore;
}

export async function createApp(deps: AppDeps): Promise<Hono> {
  const app = new Hono();

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  mountDiscovery(app, deps.config);
  mountJwks(app, deps.config);
  mountToken(app, deps.config, deps.store);
  mountUserinfo(app, deps.config, deps.store);
  mountRevoke(app, deps.config, deps.store);

  app.route('/admin', buildAdminRouter(deps.store, deps.config.adminToken));

  return app;
}
