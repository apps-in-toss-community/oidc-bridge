import { Hono } from 'hono';
import type { ProbeItem } from '../cli/output.js';
import { mountSessionRoute } from './admin/session-route.js';
import { type MountAdminRoutesOptions, mountAdminRoutes } from './apps/routes.js';
import type { OidcConfig } from './config.js';
import type { Logger } from './core/logger.js';
import { pinoHttp } from './middleware/pino-http.js';
import { rateLimit } from './middleware/rate-limit-route.js';
import { requestId } from './middleware/request-id.js';
import { discoveryRoute } from './oidc/discovery-route.js';
import { jwksRoute } from './oidc/jwks-route.js';
import { rawTokensRoute } from './oidc/raw-tokens-route.js';
import type { RevocationStore } from './oidc/revocation-store.js';
import { revokeRoute } from './oidc/revoke-route.js';
import type { SigningKeyRegistry } from './oidc/signing-keys.js';
import { tokenRoute } from './oidc/token-route.js';
import { createTokenService } from './oidc/token-service.js';
import { userinfoRoute } from './oidc/userinfo-route.js';
import type { SessionService } from './sessions/service.js';
import { recordHealthz } from './status/last-healthz.js';
import { mountStatusRoute } from './status/route.js';
import type { Storage } from './storage/interface.js';
import type { TossAdapter } from './toss/adapter.js';

export interface ObservabilityOptions {
  logger: Logger;
  ipHashSalt: string;
}

export interface RateLimitOptions {
  enabled: boolean;
  ipPerMin: number;
  appPerMin: number;
}

export interface StatusOptions {
  version: string;
  buildSha: string;
  probes: () => Promise<ProbeItem[]>;
}

export interface CreateAppOptions {
  admin?: MountAdminRoutesOptions;
  oidc?: {
    config: OidcConfig;
    signingKeyRegistry: SigningKeyRegistry;
    storage: Storage;
    tossAdapter: TossAdapter;
    resolveAppSealingKey: (input: {
      appId: string;
      sealingKeyVersion: number;
    }) => Promise<Uint8Array>;
    revocationStore: RevocationStore;
    now?: () => number;
  };
  // Phase 6 placeholder. Mounted only when the env flag is on AND a service
  // is supplied at bootstrap. Default-off: routes are not registered →
  // Hono returns 404, indistinguishable from "endpoint does not exist."
  session?: {
    service: SessionService;
  };
  /** Phase 8 — request-id + structured request log line. Both are no-ops if absent. */
  observability?: ObservabilityOptions;
  /** Phase 8 — sliding-window rate limit on `/oidc/*` and `/admin/*`. */
  rateLimit?: RateLimitOptions;
  /** Phase 8 — `GET /status` page. */
  status?: StatusOptions;
}

/**
 * Build the Hono app.
 *
 * Factory rather than module-level singleton so tests can construct
 * fresh instances and so server.ts stays a thin entrypoint.
 *
 * Middleware order (when configured):
 *   1. requestId (so logs + downstream see x-request-id)
 *   2. pinoHttp  (start latency timer right after id is set)
 *   3. /healthz + /status registered (BEFORE rate-limit so they're exempt)
 *   4. rateLimit scoped to /oidc/* and /admin/*
 *   5. Route blocks (admin, session, oidc)
 */
export function createApp(opts: CreateAppOptions = {}): Hono {
  const app = new Hono();

  if (opts.observability) {
    app.use('*', requestId());
    app.use(
      '*',
      pinoHttp({ logger: opts.observability.logger, ipSalt: opts.observability.ipHashSalt }),
    );
  }

  app.get('/healthz', (c) => {
    recordHealthz();
    return c.json({ status: 'ok' });
  });

  if (opts.status) {
    app.route('/', mountStatusRoute(opts.status));
  }

  if (opts.rateLimit) {
    const rl = rateLimit(opts.rateLimit);
    app.use('/oidc/*', rl);
    app.use('/admin/*', rl);
  }

  if (opts.admin) {
    mountAdminRoutes(app, opts.admin);
  }
  if (opts.session) {
    app.route('/', mountSessionRoute({ service: opts.session.service }));
  }
  if (opts.oidc) {
    const now = opts.oidc.now ?? (() => Math.floor(Date.now() / 1000));
    app.route('/', discoveryRoute({ issuer: opts.oidc.config.issuer }));
    app.route('/', jwksRoute({ registry: opts.oidc.signingKeyRegistry }));
    const tokenService = createTokenService({
      adapter: opts.oidc.tossAdapter,
      registry: opts.oidc.signingKeyRegistry,
      issuer: opts.oidc.config.issuer,
      idTokenTtlSeconds: opts.oidc.config.idTokenTtlSeconds,
      resolveAppSealingKey: opts.oidc.resolveAppSealingKey,
      now,
    });
    app.route(
      '/',
      tokenRoute({
        storage: opts.oidc.storage,
        tokenService,
        resolveAppSealingKey: opts.oidc.resolveAppSealingKey,
      }),
    );
    app.route(
      '/',
      userinfoRoute({
        storage: opts.oidc.storage,
        tossAdapter: opts.oidc.tossAdapter,
        resolveAppSealingKey: opts.oidc.resolveAppSealingKey,
        revocationStore: opts.oidc.revocationStore,
      }),
    );
    app.route(
      '/',
      revokeRoute({
        storage: opts.oidc.storage,
        tossAdapter: opts.oidc.tossAdapter,
        resolveAppSealingKey: opts.oidc.resolveAppSealingKey,
        revocationStore: opts.oidc.revocationStore,
      }),
    );
    app.route(
      '/',
      rawTokensRoute({
        storage: opts.oidc.storage,
        resolveAppSealingKey: opts.oidc.resolveAppSealingKey,
        revocationStore: opts.oidc.revocationStore,
        now,
      }),
    );
  }
  return app;
}
