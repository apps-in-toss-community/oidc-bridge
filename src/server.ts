import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { createLogger } from './logger.js';

const log = createLogger();
const port = Number(process.env.PORT ?? 8080);
const app = createApp();

serve({ fetch: app.fetch, port }, (info) => {
  log.info({ port: info.port, addr: info.address }, 'oidc-bridge listening');
});

const shutdown = (signal: NodeJS.Signals) => {
  log.info({ signal }, 'received shutdown signal');
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
