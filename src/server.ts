import { serve } from '@hono/node-server';
import { createApp } from './app.js';

const port = Number(process.env.PORT ?? 8080);
const app = createApp();

serve({ fetch: app.fetch, port }, (info) => {
  // Intentionally minimal — structured logging comes in a follow-up PR.
  console.log(`oidc-bridge listening on http://localhost:${info.port}`);
});
