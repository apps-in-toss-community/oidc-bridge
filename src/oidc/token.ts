import type { Hono } from 'hono';
import type { Config } from '../config.js';
import { OAuthError, oauthErrorBody } from '../errors.js';
import { verifyClientSecret } from '../tenants/crypto.js';
import type { TenantStore } from '../tenants/store.js';
import { buildAgent } from '../toss/client.js';
import { generateToken } from '../toss/generate-token.js';
import { loginMe } from '../toss/login-me.js';
import { refreshToken as tossRefresh } from '../toss/refresh-token.js';
import { isObject } from '../utils/json.js';
import { mapToIdTokenClaims } from './claim-mapping.js';
import { extractClientCredentials } from './client-auth.js';
import { signIdToken } from './id-token.js';
import { type SealedPayload, sealAccessToken, unsealAccessToken } from './sealed-token.js';

/** Sealed refresh-token lifetime (14 days). */
const REFRESH_TOKEN_TTL_SECONDS = 14 * 24 * 3600;

// Precomputed bcrypt-cost-12 hash of a random string, used to equalize
// timing on unknown-tenant lookups. The corresponding plaintext is never
// recorded. Prevents tenant-id enumeration via response-time analysis
// (timing oracle): without this, an unknown tenant returns immediately (~ms)
// while a known tenant + wrong secret runs bcrypt (~50–100ms), making
// valid tenant IDs detectable by timing.
const DUMMY_BCRYPT_HASH = '$2a$12$UpGRDA6x73lMTwuXaDLege5m5mQSsVc0HaqaPlObE064uJyI6JLti';

function decodeJwtExp(jwt: string): number | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1] as string, 'base64url').toString('utf8')) as {
      exp?: unknown;
    };
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch {
    return null;
  }
}

export function mountToken(app: Hono, config: Config, store: TenantStore): void {
  app.post('/oidc/token', async (c) => {
    try {
      const ctype = (c.req.header('content-type') ?? '').toLowerCase();
      const params: Record<string, string> = {};
      if (ctype.includes('application/x-www-form-urlencoded')) {
        const text = await c.req.text();
        for (const [k, v] of new URLSearchParams(text)) params[k] = v;
      } else {
        const j: unknown = await c.req.json().catch(() => ({}));
        if (isObject(j)) {
          for (const [k, v] of Object.entries(j)) {
            if (typeof v === 'string') params[k] = v;
          }
        }
      }

      let creds: ReturnType<typeof extractClientCredentials>;
      try {
        creds = extractClientCredentials({
          authorizationHeader: c.req.header('authorization'),
          bodyClientId: params.client_id,
          bodyClientSecret: params.client_secret,
        });
      } catch (e) {
        throw new OAuthError('invalid_client', (e as Error).message, 401);
      }
      if (!creds) throw new OAuthError('invalid_client', 'no client authentication', 401);

      const tenant = await store.get(creds.client_id);
      if (!tenant) {
        // Run a dummy bcrypt comparison to equalize timing with the known-tenant
        // + wrong-secret path, preventing tenant-id enumeration via timing oracle.
        await verifyClientSecret(creds.client_secret, [DUMMY_BCRYPT_HASH]);
        throw new OAuthError('invalid_client', 'unknown client', 401);
      }
      const ok = await verifyClientSecret(
        creds.client_secret,
        tenant.client_secret_hashes.map((h) => h.hash),
      );
      if (!ok) throw new OAuthError('invalid_client', 'bad client_secret', 401);

      const agent = buildAgent(tenant.mtls);
      const referrer = tenant.environment === 'sandbox' ? 'SANDBOX' : 'DEFAULT';
      const requestedScopes = (params.scope ?? '').split(/\s+/).filter(Boolean);

      let tossAt: string;
      let tossRt: string;
      if (params.grant_type === 'authorization_code') {
        if (!params.code) throw new OAuthError('invalid_request', 'code required', 400);
        const r = await generateToken({
          apiBase: config.tossApiBase,
          agent,
          authorizationCode: params.code,
          referrer,
        });
        if (!r.ok) throw new OAuthError('invalid_grant', r.description ?? r.reason, 400);
        tossAt = r.value.accessToken;
        tossRt = r.value.refreshToken;
      } else if (params.grant_type === 'refresh_token') {
        if (!params.refresh_token)
          throw new OAuthError('invalid_request', 'refresh_token required', 400);
        let unsealed: SealedPayload;
        try {
          unsealed = unsealAccessToken({
            token: params.refresh_token,
            masterKey: config.masterKey,
            sealingKeyVersionOf: () => tenant.sealing_key_version,
          });
        } catch {
          throw new OAuthError('invalid_grant', 'bad refresh_token', 400);
        }
        if (unsealed.tenant_id !== tenant.id) {
          throw new OAuthError('invalid_grant', 'refresh_token tenant mismatch', 400);
        }
        const r = await tossRefresh({
          apiBase: config.tossApiBase,
          agent,
          refreshToken: unsealed.toss_refresh_token,
          referrer,
        });
        if (!r.ok) throw new OAuthError('invalid_grant', r.description ?? r.reason, 400);
        tossAt = r.value.accessToken;
        tossRt = r.value.refreshToken ?? unsealed.toss_refresh_token;
      } else {
        throw new OAuthError('unsupported_grant_type', `unknown grant ${params.grant_type}`, 400);
      }

      const me = await loginMe({ apiBase: config.tossApiBase, agent, tossAccessToken: tossAt });
      if (!me.ok) throw new OAuthError('invalid_grant', me.description ?? me.reason, 400);

      const now = Math.floor(Date.now() / 1000);
      const tossExp = decodeJwtExp(tossAt) ?? now + 3600;
      const claims = mapToIdTokenClaims({
        issuer: config.issuer,
        audience: tenant.id,
        now,
        tossAccessTokenExp: tossExp,
        loginMe: me.value,
        requestedScopes,
      });
      const idToken = await signIdToken({ claims, signingKeyPem: config.signingKeyPem });

      const accessToken = sealAccessToken({
        payload: {
          tenant_id: tenant.id,
          toss_access_token: tossAt,
          toss_refresh_token: tossRt,
          exp: tossExp,
        },
        masterKey: config.masterKey,
        sealingKeyVersion: tenant.sealing_key_version,
      });
      const refreshTokenOut = sealAccessToken({
        payload: {
          tenant_id: tenant.id,
          toss_access_token: tossAt,
          toss_refresh_token: tossRt,
          exp: now + REFRESH_TOKEN_TTL_SECONDS,
        },
        masterKey: config.masterKey,
        sealingKeyVersion: tenant.sealing_key_version,
      });

      return c.json({
        access_token: accessToken,
        id_token: idToken,
        refresh_token: refreshTokenOut,
        token_type: 'Bearer',
        expires_in: tossExp - now,
        scope: claims.scope,
      });
    } catch (err) {
      if (err instanceof OAuthError) return c.json(oauthErrorBody(err), err.status);
      throw err;
    }
  });
}
