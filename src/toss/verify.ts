/**
 * Toss authorizationCode → verified claims.
 *
 * Flow:
 *   1. POST {TOSS_API_BASE}/api-partner/v1/apps-in-toss/user/oauth2/generate-token
 *      with `{ authorizationCode, referrer }`. Partner credentials are sent as
 *      HTTP Basic Auth (`TOSS_CLIENT_ID:TOSS_CLIENT_SECRET`) — see
 *      CLAUDE.md § Toss verification assumption #1.
 *   2. Decode the returned accessToken (JWT, 3 segments). Signature
 *      verification is a documented pre-stable gap: v0 trusts the
 *      generate-token response as the verification signal. See CLAUDE.md
 *      § pre-stable gap.
 *   3. Map into the normalized `VerifiedClaims` shape.
 */

export type Referrer = 'DEFAULT' | 'SANDBOX';

export interface VerifyRequest {
  authorizationCode: string;
  referrer: Referrer;
}

export interface VerifiedClaims {
  sub: string;
  provider: 'toss';
  claims: {
    userKey?: string;
    scopes?: string[];
    agreedTerms?: string[];
  };
  tossAccessTokenExpiresAt?: number;
}

export type VerifyErrorCode =
  | 'toss_rejected'
  | 'upstream_error'
  | 'server_misconfigured'
  | 'invalid_upstream_response';

export type VerifyResult =
  | { ok: true; claims: VerifiedClaims }
  | {
      ok: false;
      status: 400 | 401 | 500 | 502;
      error: VerifyErrorCode;
      description: string;
    };

const DEFAULT_TOSS_API_BASE = 'https://apps-in-toss-api.toss.im';
const GENERATE_TOKEN_PATH = '/api-partner/v1/apps-in-toss/user/oauth2/generate-token';

interface TossGenerateTokenResponse {
  accessToken: string;
  refreshToken?: string;
  tokenType?: string;
  expiresIn?: number;
  scope?: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTossGenerateTokenResponse(value: unknown): value is TossGenerateTokenResponse {
  if (!isObject(value)) return false;
  if (typeof value.accessToken !== 'string' || value.accessToken.length === 0) return false;
  return true;
}

interface DecodedAccessToken {
  sub?: string;
  scope?: string;
  exp?: number;
  userKey?: string;
}

function decodeJwtPayload(jwt: string): DecodedAccessToken | null {
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  const payload = parts[1];
  if (!payload) return null;
  try {
    const json = Buffer.from(payload, 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    if (!isObject(parsed)) return null;
    const out: DecodedAccessToken = {};
    if (typeof parsed.sub === 'string') out.sub = parsed.sub;
    if (typeof parsed.scope === 'string') out.scope = parsed.scope;
    if (typeof parsed.exp === 'number') out.exp = parsed.exp;
    if (typeof parsed.userKey === 'string') out.userKey = parsed.userKey;
    return out;
  } catch {
    return null;
  }
}

function basicAuthHeader(clientId: string, clientSecret: string): string {
  const encoded = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  return `Basic ${encoded}`;
}

export async function verifyTossAuthorizationCode(req: VerifyRequest): Promise<VerifyResult> {
  const clientId = process.env.TOSS_CLIENT_ID;
  const clientSecret = process.env.TOSS_CLIENT_SECRET;
  const apiBase = process.env.TOSS_API_BASE ?? DEFAULT_TOSS_API_BASE;

  if (!clientId || !clientSecret) {
    return {
      ok: false,
      status: 500,
      error: 'server_misconfigured',
      description: 'TOSS_CLIENT_ID and TOSS_CLIENT_SECRET must be set on the server.',
    };
  }

  const url = `${apiBase}${GENERATE_TOKEN_PATH}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        authorization: basicAuthHeader(clientId, clientSecret),
      },
      body: JSON.stringify({
        authorizationCode: req.authorizationCode,
        referrer: req.referrer,
      }),
    });
  } catch (_err) {
    // TODO(M3-observability): surface network-error details via structured logger.
    return {
      ok: false,
      status: 502,
      error: 'upstream_error',
      description: 'Failed to reach Toss partner API.',
    };
  }

  // 400/401 → the user's authorizationCode itself was bad. 403 stays out of
  // this arm on purpose: Toss returning 403 usually signals a partner-creds
  // issue (server misconfiguration), not a per-user bad code, so we fall
  // through to upstream_error rather than masking it as toss_rejected.
  if (response.status === 400 || response.status === 401) {
    return {
      ok: false,
      status: 401,
      error: 'toss_rejected',
      description: 'Toss rejected the authorizationCode.',
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: 502,
      error: 'upstream_error',
      description: `Toss partner API returned ${response.status}.`,
    };
  }

  let json: unknown;
  try {
    json = await response.json();
  } catch {
    return {
      ok: false,
      status: 502,
      error: 'invalid_upstream_response',
      description: 'Toss partner API returned a non-JSON response.',
    };
  }

  if (!isTossGenerateTokenResponse(json)) {
    return {
      ok: false,
      status: 502,
      error: 'invalid_upstream_response',
      description: 'Toss partner API response is missing accessToken.',
    };
  }

  const decoded = decodeJwtPayload(json.accessToken);
  if (!decoded?.sub) {
    return {
      ok: false,
      status: 502,
      error: 'invalid_upstream_response',
      description: 'Toss accessToken is not a decodable JWT with a `sub` claim.',
    };
  }

  const scopes =
    typeof json.scope === 'string' && json.scope.length > 0
      ? json.scope.split(/\s+/).filter((s) => s.length > 0)
      : decoded.scope
        ? decoded.scope.split(/\s+/).filter((s) => s.length > 0)
        : undefined;

  const claims: VerifiedClaims['claims'] = {};
  if (decoded.userKey) claims.userKey = decoded.userKey;
  if (scopes && scopes.length > 0) claims.scopes = scopes;

  // Trust boundary: `decoded.sub` is read from a JWT whose signature we do not
  // verify in v0 — see CLAUDE.md § pre-stable gap. Do not extend this function
  // to grant additional authority based on AT claims until signature
  // verification lands (see TODO.md High Priority).
  const verified: VerifiedClaims = {
    sub: decoded.sub,
    provider: 'toss',
    claims,
  };

  if (typeof decoded.exp === 'number') {
    verified.tossAccessTokenExpiresAt = decoded.exp;
  } else if (typeof json.expiresIn === 'number') {
    verified.tossAccessTokenExpiresAt = Math.floor(Date.now() / 1000) + json.expiresIn;
  }

  return { ok: true, claims: verified };
}
