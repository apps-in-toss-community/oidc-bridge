import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { createTenantStore } from './tenants/store.js';

const port = Number(process.env.PORT ?? 8080);
const config = loadConfig();
const store = await createTenantStore(config);
const app = await createApp({ config, store });

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`oidc-bridge listening on http://localhost:${info.port}`);
});
