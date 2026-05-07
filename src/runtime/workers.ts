/**
 * Cloudflare Workers entry point for oidc-bridge (Phase 09c).
 *
 * Wires WebCrypto / D1 / Workers-binding implementations of every port and
 * delegates to the same `createApp(...)` factory used by the Node entry.
 *
 * Workers types (D1Database, ExecutionContext) are imported as `type` from
 * `@cloudflare/workers-types`. This keeps them scoped to this file —
 * a `/// <reference>` directive would pollute global lib for the whole project
 * (e.g. tightening Node's TextDecoder constructor signature).
 *
 * **Phase 09c gap**: mTLS to Toss is not yet implemented for Workers. The
 * Workers `fetch` handler intercepts `POST /oidc/token` before it reaches the
 * Hono routes and returns 501 `temporarily_unavailable`. All other routes
 * (`/healthz`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`,
 * `/admin/*`, etc.) are fully functional. Phase 12c will land
 * `MtlsClient.WorkersBinding` and remove the intercept.
 */

import type { D1Database, ExecutionContext } from '@cloudflare/workers-types';
import { createApp } from '../app.js';
import {
  loadBridgeFlags,
  loadObservabilityConfig,
  loadOidcConfig,
  loadRateLimitConfig,
} from '../config.js';
import { createAppSealingKeyResolver } from '../oidc/app-sealing-key.js';
import { createInMemoryRevocationStore } from '../oidc/revocation-store.js';
import { createSigningKeyRegistry } from '../oidc/signing-keys.js';
import { createD1Storage } from '../storage/d1.js';
import { RealTossAdapter } from '../toss/real-adapter.js';
import { createWorkersMasterKeyProvider } from './workers-master-key-provider.js';
import { createWorkersStubMtlsFactory } from './workers-mtls.js';

/**
 * Shape of the Cloudflare Workers env bindings expected by this worker.
 *
 * Env vars that the config loaders read (OIDC_ISSUER, OIDC_ACTIVE_KID,
 * OIDC_SIGNING_KEY_*_PEM, MASTER_KEY_V*_HEX, etc.) are accessed via the
 * string-index signature.  Wrangler surfaces these as plain string bindings
 * in `wrangler.toml` [vars] / Workers Secrets.
 */
export interface WorkersEnv {
  /** D1 database binding (wrangler.toml: [[d1_databases]] binding = "DB"). */
  DB: D1Database;
  [key: string]: unknown;
}

/** Cast Workers env to the `Record<string, string | undefined>` shape the config loaders expect. */
function toProcessEnvShape(env: WorkersEnv): NodeJS.ProcessEnv {
  return env as unknown as NodeJS.ProcessEnv;
}

const NOT_IMPLEMENTED_BODY = JSON.stringify({
  error: 'temporarily_unavailable',
  error_description:
    'Workers runtime: mTLS to Toss not yet implemented (Phase 12c). Use the Node/Docker deployment until then.',
});

export default {
  async fetch(req: Request, env: WorkersEnv, _ctx: ExecutionContext): Promise<Response> {
    // --- Phase 12c gap intercept ------------------------------------------
    // Intercept POST /oidc/token BEFORE app construction so the 501 is
    // always returned cleanly regardless of whether the app is even wired up.
    // This is the "route-level interceptor" approach: explicit, zero-leak,
    // and easy to remove in Phase 12c (one `if` block deletion).
    const url = new URL(req.url);
    if (url.pathname === '/oidc/token' && req.method === 'POST') {
      return new Response(NOT_IMPLEMENTED_BODY, {
        status: 501,
        headers: { 'content-type': 'application/json' },
      });
    }

    // --- Storage ----------------------------------------------------------
    // Migrations are applied once at deploy time (via `wrangler d1 migrations apply`
    // or a separate CLI step). The fetch handler assumes the schema is already present.
    const storage = createD1Storage({ db: env.DB });

    // --- Config -----------------------------------------------------------
    const processEnvShape = toProcessEnvShape(env);
    const oidcConfig = loadOidcConfig(processEnvShape);
    const observabilityConfig = loadObservabilityConfig(processEnvShape);
    const rateLimitConfig = loadRateLimitConfig(processEnvShape);
    const flags = loadBridgeFlags(processEnvShape);

    // --- Ports ------------------------------------------------------------
    const masterKeyProvider = createWorkersMasterKeyProvider({ env });

    const signingKeyRegistry = await createSigningKeyRegistry({
      activeKid: oidcConfig.activeKid,
      signingKeys: oidcConfig.signingKeys,
    });

    const resolveAppSealingKey = createAppSealingKeyResolver({ provider: masterKeyProvider });
    const revocationStore = createInMemoryRevocationStore();

    const tossApiBase =
      typeof env.TOSS_API_BASE === 'string'
        ? env.TOSS_API_BASE
        : 'https://apps-in-toss-api.toss.im';

    const tossAdapter = new RealTossAdapter({
      apiBase: tossApiBase,
      mtlsFactory: createWorkersStubMtlsFactory(),
    });

    // --- Session (optional, flag-gated) -----------------------------------
    const session = flags.enableSessionLogin
      ? undefined // Workers session wiring deferred — Phase 11c
      : undefined;

    // --- App --------------------------------------------------------------
    const app = createApp({
      oidc: {
        config: oidcConfig,
        signingKeyRegistry,
        storage,
        tossAdapter,
        resolveAppSealingKey,
        revocationStore,
      },
      ...(session ? { session } : {}),
      rateLimit: rateLimitConfig,
      status: {
        version: observabilityConfig.version,
        buildSha: observabilityConfig.buildSha,
        probes: async () => [],
      },
    });

    return app.fetch(req);
  },
};
