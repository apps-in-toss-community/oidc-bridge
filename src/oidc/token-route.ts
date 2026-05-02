import { Hono } from 'hono';
import { appendAudit } from '../apps/audit.js';
import type { Storage } from '../storage/interface.js';
import { toOAuthError } from './errors.js';
import { originIsAllowed } from './origin-check.js';
import { peekSealedTokenVersion, unwrapSealedToken } from './sealed-token.js';
import { tokenBody } from './token-schemas.js';
import type { TokenService } from './token-service.js';

export interface TokenRouteOpts {
  storage: Storage;
  tokenService: TokenService;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
}

export function tokenRoute(opts: TokenRouteOpts) {
  const app = new Hono();

  app.post('/oidc/token', async (c) => {
    let raw: unknown;
    const ct = c.req.header('content-type') ?? '';
    try {
      if (ct.includes('application/json')) {
        raw = await c.req.json();
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        raw = await c.req.parseBody();
      } else {
        const e = toOAuthError({
          code: 'invalid_request',
          description: 'unsupported content-type',
        });
        return c.json(e.body, e.status as never);
      }
    } catch {
      const e = toOAuthError({ code: 'invalid_request', description: 'malformed body' });
      return c.json(e.body, e.status as never);
    }

    const parsed = tokenBody.safeParse(raw);
    if (!parsed.success) {
      const e = toOAuthError({
        code: 'invalid_request',
        description: parsed.error.issues[0]?.message ?? 'bad body',
      });
      return c.json(e.body, e.status as never);
    }

    const body = parsed.data;
    const appRow = await opts.storage.getAppByClientId(body.client_id);
    if (!appRow) {
      const e = toOAuthError({ code: 'invalid_client', description: 'unknown client_id' });
      return c.json(e.body, e.status as never);
    }

    if (appRow.ownershipStatus !== 'verified') {
      const e = toOAuthError({ code: 'app_not_verified', description: 'app ownership not active' });
      return c.json(e.body, e.status as never);
    }

    const origin = c.req.header('origin');
    if (!originIsAllowed(origin, appRow.allowedOrigins)) {
      const e = toOAuthError({ code: 'invalid_client', description: 'origin not allowed' });
      return c.json(e.body, e.status as never);
    }

    try {
      if (body.grant_type === 'authorization_code') {
        const out = await opts.tokenService.authorizationCode({
          app: {
            id: appRow.id,
            clientId: appRow.clientId,
            sealingKeyVersion: appRow.sealingKeyVersion,
          },
          authorizationCode: body.code,
          ...(body.referrer !== undefined ? { referrer: body.referrer } : {}),
        });
        await appendAudit({
          storage: opts.storage,
          actor: appRow.id,
          action: 'oidc.token.issue',
          target: appRow.id,
          details: { grant_type: 'authorization_code' },
        });
        return c.json(out);
      }

      // refresh_token branch
      let version: number;
      try {
        version = peekSealedTokenVersion(body.refresh_token);
      } catch {
        const e = toOAuthError({ code: 'invalid_grant', description: 'refresh_token format' });
        return c.json(e.body, e.status as never);
      }

      let unwrapped: ReturnType<typeof unwrapSealedToken>;
      try {
        const sealingKey = await opts.resolveAppSealingKey({
          appId: appRow.id,
          sealingKeyVersion: version,
        });
        unwrapped = unwrapSealedToken({
          token: body.refresh_token,
          resolveKey: () => sealingKey,
          expectedAppId: appRow.id,
        });
      } catch {
        const e = toOAuthError({ code: 'invalid_grant', description: 'refresh_token rejected' });
        return c.json(e.body, e.status as never);
      }

      const out = await opts.tokenService.refresh({
        app: { id: appRow.id, clientId: appRow.clientId, sealingKeyVersion: version },
        unwrappedRt: { tossRt: unwrapped.tossRt, tossUserKey: unwrapped.tossUserKey },
      });
      await appendAudit({
        storage: opts.storage,
        actor: appRow.id,
        action: 'oidc.token.refresh',
        target: appRow.id,
        details: {},
      });
      return c.json(out);
    } catch (err) {
      const oe = toOAuthError(err as Error);
      return c.json(oe.body, oe.status as never);
    }
  });

  return app;
}
