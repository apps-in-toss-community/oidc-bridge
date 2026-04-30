import type { Hono } from 'hono';
import type { Config } from '../config.js';
import type { TenantStore } from '../tenants/store.js';
import { removeByAccessToken } from '../toss/access-remove.js';
import { buildAgent } from '../toss/client.js';
import { isObject } from '../utils/json.js';
import { unsealAccessToken } from './sealed-token.js';

/**
 * RFC 7009 §2.2: respond 200 whether revocation succeeded or the token was
 * invalid. We call Toss /access/remove-by-access-token on best effort.
 */
export function mountRevoke(app: Hono, config: Config, store: TenantStore): void {
  app.post('/oidc/revoke', async (c) => {
    const ok = (): Response => c.body(null, 200);
    const ctype = (c.req.header('content-type') ?? '').toLowerCase();
    let token: string | undefined;
    if (ctype.includes('application/x-www-form-urlencoded')) {
      const text = await c.req.text();
      const params = new URLSearchParams(text);
      token = params.get('token') ?? undefined;
    } else {
      const j: unknown = await c.req.json().catch(() => ({}));
      if (isObject(j) && typeof j.token === 'string') token = j.token;
    }
    if (!token) return ok();
    try {
      // M1 ships a single sealing_key_version per tenant. The version is in
      // the AAD header, so AEAD already enforces version equality. Post-M1
      // rotation will turn this into a two-attempt unseal (active, then prev).
      const unsealed = unsealAccessToken({
        token,
        masterKey: config.masterKey,
        sealingKeyVersionOf: () => 1,
      });
      const tenant = await store.get(unsealed.tenant_id);
      if (!tenant) return ok();
      const agent = buildAgent(tenant.mtls);
      await removeByAccessToken({
        apiBase: config.tossApiBase,
        agent,
        tossAccessToken: unsealed.toss_access_token,
      });
    } catch {
      // RFC 7009: 200 even on error
    }
    return ok();
  });
}
