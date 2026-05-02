import { Hono } from 'hono';
import type { SigningKeyRegistry } from './signing-keys.js';

export function jwksRoute(opts: { registry: SigningKeyRegistry }) {
  const app = new Hono();
  app.get('/.well-known/jwks.json', (c) => {
    c.header('cache-control', 'public, max-age=300');
    return c.json(opts.registry.jwks());
  });
  return app;
}
