import { Hono } from 'hono';

/**
 * Build the Hono app.
 *
 * Factory rather than module-level singleton so tests can construct
 * fresh instances and so server.ts stays a thin entrypoint.
 */
export function createApp(): Hono {
  const app = new Hono();
  app.get('/healthz', (c) => c.json({ status: 'ok' }));
  return app;
}
