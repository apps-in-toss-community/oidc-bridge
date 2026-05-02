import { Hono } from 'hono';
import { type MountAdminRoutesOptions, mountAdminRoutes } from './apps/routes.js';
import type { OidcConfig } from './config.js';
import { discoveryRoute } from './oidc/discovery-route.js';
import { jwksRoute } from './oidc/jwks-route.js';
import type { RevocationStore } from './oidc/revocation-store.js';
import { revokeRoute } from './oidc/revoke-route.js';
import type { SigningKeyRegistry } from './oidc/signing-keys.js';
import { tokenRoute } from './oidc/token-route.js';
import { createTokenService } from './oidc/token-service.js';
import { userinfoRoute } from './oidc/userinfo-route.js';
import type { Storage } from './storage/interface.js';
import type { TossAdapter } from './toss/adapter.js';

export interface CreateAppOptions {
  admin?: MountAdminRoutesOptions;
  oidc?: {
    config: OidcConfig;
    signingKeyRegistry: SigningKeyRegistry;
    storage: Storage;
    tossAdapter: TossAdapter;
    resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
    revocationStore: RevocationStore;
    now?: () => number;
  };
}

/**
 * Build the Hono app.
 *
 * Factory rather than module-level singleton so tests can construct
 * fresh instances and so server.ts stays a thin entrypoint.
 */
export function createApp(opts: CreateAppOptions = {}): Hono {
  const app = new Hono();
  app.get('/healthz', (c) => c.json({ status: 'ok' }));
  if (opts.admin) {
    mountAdminRoutes(app, opts.admin);
  }
  if (opts.oidc) {
    app.route('/', discoveryRoute({ issuer: opts.oidc.config.issuer }));
    app.route('/', jwksRoute({ registry: opts.oidc.signingKeyRegistry }));
    const tokenService = createTokenService({
      adapter: opts.oidc.tossAdapter,
      registry: opts.oidc.signingKeyRegistry,
      issuer: opts.oidc.config.issuer,
      idTokenTtlSeconds: opts.oidc.config.idTokenTtlSeconds,
      resolveAppSealingKey: opts.oidc.resolveAppSealingKey,
      now: opts.oidc.now ?? (() => Math.floor(Date.now() / 1000)),
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
  }
  return app;
}
