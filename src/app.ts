import { Hono } from 'hono';
import type { Config } from './config.js';
import { mountRevoke } from './oidc/revoke.js';
import { mountToken } from './oidc/token.js';
import { mountUserinfo } from './oidc/userinfo.js';
import type { TenantStore } from './tenants/store.js';
import { verifyTossAuthorizationCode } from './toss/verify.js';
import { isObject as isJsonObject } from './utils/json.js';

/**
 * Build the Hono app.
 *
 * When called with `{ config, store }`, mounts the M1 OIDC routes
 * (POST /oidc/token, GET /oidc/userinfo, POST /oidc/revoke) in addition
 * to the legacy /verify and /healthz endpoints.
 *
 * When called without arguments, returns only the legacy surface — used by
 * the existing app.test.ts suite until Task 7 extends the factory.
 */
export async function createApp(args?: { config: Config; store: TenantStore }): Promise<Hono> {
  const app = new Hono();

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  /**
   * POST /verify
   *
   * Legacy endpoint (M0.5). Will be removed in the same release as M1.
   * See CLAUDE.md for migration notes.
   */
  app.post('/verify', async (c) => {
    const body: unknown = await c.req.json().catch(() => null);

    if (!isJsonObject(body)) {
      return c.json(
        { error: 'invalid_request', error_description: 'body must be a JSON object' },
        400,
      );
    }

    const { authorizationCode, referrer } = body;

    if (typeof authorizationCode !== 'string' || authorizationCode.length === 0) {
      return c.json(
        {
          error: 'invalid_request',
          error_description: 'authorizationCode is required and must be a non-empty string',
        },
        400,
      );
    }

    if (referrer !== 'DEFAULT' && referrer !== 'SANDBOX') {
      return c.json(
        {
          error: 'invalid_request',
          error_description: "referrer must be 'DEFAULT' or 'SANDBOX'",
        },
        400,
      );
    }

    const result = await verifyTossAuthorizationCode({ authorizationCode, referrer });

    if (!result.ok) {
      return c.json({ error: result.error, error_description: result.description }, result.status);
    }

    return c.json(result.claims);
  });

  if (args !== undefined) {
    mountToken(app, args.config, args.store);
    mountUserinfo(app, args.config, args.store);
    mountRevoke(app, args.config, args.store);
  }

  return app;
}
