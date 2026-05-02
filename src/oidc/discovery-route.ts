import { Hono } from 'hono';
import { buildDiscovery } from './discovery.js';

export function discoveryRoute(opts: { issuer: string }) {
  const app = new Hono();
  app.get('/.well-known/openid-configuration', (c) =>
    c.json(buildDiscovery({ issuer: opts.issuer })),
  );
  return app;
}
