import { Hono } from 'hono';
import { verifyTossAuthorizationCode } from './toss/verify.js';

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

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
   * See CLAUDE.md (API 표면, Toss token verification) for the contract and flow.
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

  return app;
}
