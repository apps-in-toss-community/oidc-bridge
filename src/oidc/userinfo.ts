import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { OAuthError, oauthErrorBody } from '../errors.js';
import type { TenantStore } from '../tenants/store.js';
import { buildAgent } from '../toss/client.js';
import { loginMe } from '../toss/login-me.js';
import { type SealedPayload, unsealAccessToken } from './sealed-token.js';

export function mountUserinfo(app: Hono, config: Config, store: TenantStore): void {
  app.get('/oidc/userinfo', async (c) => {
    try {
      const auth = c.req.header('authorization') ?? '';
      if (!auth.startsWith('Bearer ')) throw new OAuthError('invalid_token', 'missing Bearer', 401);
      const token = auth.slice('Bearer '.length).trim();

      // M1 ships a single sealing_key_version per tenant. The version is in
      // the AAD header, so AEAD already enforces version equality. Post-M1
      // rotation will turn this into a two-attempt unseal (active, then prev).
      let unsealed: SealedPayload;
      try {
        unsealed = unsealAccessToken({
          token,
          masterKey: config.masterKey,
          sealingKeyVersionOf: () => 1,
        });
      } catch {
        throw new OAuthError('invalid_token', 'bad bearer', 401);
      }

      const tenant = await store.get(unsealed.tenant_id);
      if (!tenant) throw new OAuthError('invalid_token', 'unknown tenant', 401);

      const agent = buildAgent(tenant.mtls);
      const me = await loginMe({
        apiBase: config.tossApiBase,
        agent,
        tossAccessToken: unsealed.toss_access_token,
      });
      if (!me.ok) throw new OAuthError('invalid_token', me.description ?? me.reason, 401);

      return c.json({
        sub: String(me.value.userKey),
        provider: 'toss',
        scope: me.value.scope,
        'toss:userKey': me.value.userKey,
        'toss:agreedTerms': me.value.agreedTerms,
        name: me.value.name,
        phone: me.value.phone,
        birthday: me.value.birthday,
        ci: me.value.ci,
        gender: me.value.gender,
        nationality: me.value.nationality,
      });
    } catch (err) {
      if (err instanceof OAuthError) return c.json(oauthErrorBody(err), err.status);
      throw err;
    }
  });
}
