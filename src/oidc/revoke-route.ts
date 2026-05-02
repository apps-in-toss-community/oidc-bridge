import { Hono } from 'hono';
import { z } from 'zod';
import { appendAudit } from '../apps/audit.js';
import type { Storage } from '../storage/interface.js';
import type { TossAdapter } from '../toss/adapter.js';
import type { RevocationStore } from './revocation-store.js';
import {
  peekSealedTokenAppId,
  peekSealedTokenVersion,
  type SealedPayload,
  unwrapSealedToken,
} from './sealed-token.js';

export interface RevokeRouteOpts {
  storage: Storage;
  tossAdapter: TossAdapter;
  resolveAppSealingKey: (input: { appId: string; sealingKeyVersion: number }) => Promise<Buffer>;
  revocationStore: RevocationStore;
}

const revokeBody = z.object({
  token: z.string().optional(),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

export function revokeRoute(opts: RevokeRouteOpts) {
  const app = new Hono();

  app.post('/oidc/revoke', async (c) => {
    const ct = c.req.header('content-type') ?? '';
    let raw: unknown;
    try {
      if (ct.includes('application/x-www-form-urlencoded')) {
        raw = await c.req.parseBody();
      } else if (ct.includes('application/json')) {
        raw = await c.req.json();
      } else {
        return c.body(null, 200);
      }
    } catch {
      return c.body(null, 200);
    }
    const parsed = revokeBody.safeParse(raw);
    if (!parsed.success || !parsed.data.token) return c.body(null, 200);
    const token = parsed.data.token;
    if (!token.startsWith('ait_')) return c.body(null, 200);

    let appId: string;
    let version: number;
    try {
      appId = peekSealedTokenAppId(token);
      version = peekSealedTokenVersion(token);
    } catch {
      return c.body(null, 200);
    }
    const appRow = await opts.storage.getApp(appId);
    if (!appRow) return c.body(null, 200);

    let payload: SealedPayload;
    try {
      const sealingKey = await opts.resolveAppSealingKey({ appId, sealingKeyVersion: version });
      payload = unwrapSealedToken({ token, resolveKey: () => sealingKey, expectedAppId: appId });
    } catch {
      return c.body(null, 200);
    }

    opts.revocationStore.revoke({ appId, token });

    if (parsed.data.token_type_hint === 'refresh_token') {
      try {
        await opts.tossAdapter.accessRemove({ appId }, { userKey: payload.tossUserKey });
      } catch {
        // RFC 7009 always-200 — swallow upstream errors.
      }
    }

    await appendAudit({
      storage: opts.storage,
      actor: appId,
      action: 'oidc.token.revoke',
      target: appId,
      details: { hint: parsed.data.token_type_hint ?? 'unspecified' },
    });
    return c.body(null, 200);
  });

  return app;
}
