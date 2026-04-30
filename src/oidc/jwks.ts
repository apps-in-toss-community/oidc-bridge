import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { exportJwks } from './id-token.js';

export function mountJwks(app: Hono, config: Config): void {
  app.get('/.well-known/jwks.json', async (c) => {
    const jwks = await exportJwks(config.signingKeyPem);
    c.header('cache-control', 'public, max-age=300');
    return c.json(jwks);
  });
}
