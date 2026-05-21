import { type Context, Hono } from 'hono';
import { appendAudit } from '../apps/audit.js';
import type { Storage } from '../storage/interface.js';
import { parseBearer } from './bearer.js';
import type { RevocationStore } from './revocation-store.js';
import {
  peekSealedTokenAppId,
  peekSealedTokenVersion,
  type SealedPayload,
  unwrapSealedToken,
} from './sealed-token.js';

export interface RawTokensRouteOpts {
  storage: Storage;
  resolveAppSealingKey: (input: {
    appId: string;
    sealingKeyVersion: number;
  }) => Promise<Uint8Array>;
  revocationStore: RevocationStore;
  now: () => number;
}

function bearerError(c: Context, description?: string) {
  if (description) {
    c.header(
      'www-authenticate',
      `Bearer error="invalid_token", error_description="${description}"`,
    );
  } else {
    c.header('www-authenticate', 'Bearer error="invalid_token"');
  }
  return c.json({ error: 'invalid_token' }, 401);
}

export function rawTokensRoute(opts: RawTokensRouteOpts) {
  const app = new Hono();

  app.get('/oidc/raw-tokens', async (c) => {
    const token = parseBearer(c.req.header('authorization'));
    if (!token) return bearerError(c);

    let appId: string;
    let version: number;
    try {
      appId = peekSealedTokenAppId(token);
      version = peekSealedTokenVersion(token);
    } catch {
      return bearerError(c);
    }

    const appRow = await opts.storage.getApp(appId);
    if (!appRow) return bearerError(c);

    if (!appRow.rawTokensEnabled) {
      return c.json({ error: 'not_found' }, 404);
    }

    if (await opts.revocationStore.isRevoked({ appId, token })) {
      return bearerError(c, 'revoked');
    }

    let payload: SealedPayload;
    try {
      const sealingKey = await opts.resolveAppSealingKey({ appId, sealingKeyVersion: version });
      payload = await unwrapSealedToken({
        token,
        resolveKey: () => sealingKey,
        expectedAppId: appId,
        expectedTokenType: 'access',
      });
    } catch {
      return bearerError(c);
    }

    await appendAudit({
      storage: opts.storage,
      actor: appId,
      action: 'oidc.raw_tokens.read',
      target: appId,
    });

    const expiresIn = Math.max(0, payload.tossAtExp - opts.now());
    return c.json({ access_token: payload.tossAt, expires_in: expiresIn });
  });

  return app;
}
