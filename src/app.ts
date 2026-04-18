import { Hono } from 'hono';
import { verifyTossAuthorizationCode } from './toss/verify.js';

/**
 * Build the Hono app.
 *
 * Kept as a factory (rather than a module-level singleton) so tests can
 * construct fresh instances with injected dependencies, and so the server
 * bootstrap (`server.ts`) stays a thin entrypoint.
 */
export function createApp(): Hono {
  const app = new Hono();

  app.get('/healthz', (c) => c.json({ status: 'ok' }));

  /**
   * POST /verify
   *
   * Foundational endpoint: takes a Toss `authorizationCode` and returns
   * normalized claims. Every higher-level endpoint (e.g. /firebase-token)
   * wraps this path.
   *
   * See PLAN.md §3.1 for the full contract and §4 for the verification flow.
   */
  app.post('/verify', async (c) => {
    const body = await c.req.json().catch(() => null);

    if (!body || typeof body !== 'object') {
      return c.json({ error: 'invalid_request', error_description: 'body must be JSON' }, 400);
    }

    const { authorizationCode, referrer } = body as {
      authorizationCode?: unknown;
      referrer?: unknown;
    };

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

  return app;
}
