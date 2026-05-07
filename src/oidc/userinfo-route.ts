import { type Context, Hono } from 'hono';
import { appendAudit } from '../apps/audit.js';
import type { Storage } from '../storage/interface.js';
import type { LoginMeOutput, TossAdapter } from '../toss/adapter.js';
import { parseBearer } from './bearer.js';
import type { RevocationStore } from './revocation-store.js';
import type { SealedPayload } from './sealed-token.js';
import { peekSealedTokenAppId, peekSealedTokenVersion, unwrapSealedToken } from './sealed-token.js';

export interface UserinfoRouteOpts {
  storage: Storage;
  tossAdapter: TossAdapter;
  resolveAppSealingKey: (input: {
    appId: string;
    sealingKeyVersion: number;
  }) => Promise<Uint8Array>;
  revocationStore: RevocationStore;
}

function bearerError(c: Context, description: string) {
  c.header('www-authenticate', `Bearer error="invalid_token", error_description="${description}"`);
  return c.json({ error: 'invalid_token', error_description: description }, 401);
}

export function userinfoRoute(opts: UserinfoRouteOpts) {
  const app = new Hono();

  app.get('/oidc/userinfo', async (c) => {
    const token = parseBearer(c.req.header('authorization'));
    if (!token) return bearerError(c, 'missing or malformed bearer');

    let appId: string;
    let version: number;
    try {
      appId = peekSealedTokenAppId(token);
      version = peekSealedTokenVersion(token);
    } catch {
      return bearerError(c, 'malformed token');
    }

    const appRow = await opts.storage.getApp(appId);
    if (!appRow) return bearerError(c, 'unknown app');

    if (await opts.revocationStore.isRevoked({ appId, token })) {
      return bearerError(c, 'token revoked');
    }

    let payload: SealedPayload;
    try {
      const sealingKeyU8 = await opts.resolveAppSealingKey({ appId, sealingKeyVersion: version });
      // resolveKey in sealed-token.ts still returns Buffer (Task 9 will widen it).
      const sealingKey = Buffer.from(sealingKeyU8);
      payload = unwrapSealedToken({ token, resolveKey: () => sealingKey, expectedAppId: appId });
    } catch {
      return bearerError(c, 'token rejected');
    }

    let me: LoginMeOutput;
    try {
      me = await opts.tossAdapter.loginMe({ appId }, { accessToken: payload.tossAt });
    } catch {
      return c.json({ error: 'upstream_error', error_description: 'login-me failed' }, 502);
    }

    await appendAudit({
      storage: opts.storage,
      actor: appId,
      action: 'oidc.userinfo.read',
      target: appId,
    });

    const out: Record<string, unknown> = {
      sub: String(me.userKey),
      provider: 'toss',
      scope: me.scope.join(' '),
      'toss:userKey': me.userKey,
      'toss:agreedTerms': me.agreedTerms,
      'toss:tossAccessTokenExpiresAt': payload.tossAtExp,
    };
    if (me.encryptedPii) Object.assign(out, me.encryptedPii);
    return c.json(out);
  });

  return app;
}
