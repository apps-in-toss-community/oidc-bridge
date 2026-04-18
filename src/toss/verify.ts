/**
 * Toss authorizationCode → verified claims.
 *
 * The real implementation will POST to
 *   https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss/user/oauth2/generate-token
 * and map the resulting JWT accessToken (plus optional /login-me lookup)
 * into the normalized `VerifiedClaims` shape.
 *
 * See PLAN.md §4 for the full flow and the open questions that block a
 * complete implementation (partner auth scheme, JWT signature verification
 * path, /login-me opt-in semantics).
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

export type VerifyResult =
  | { ok: true; claims: VerifiedClaims }
  | {
      ok: false;
      status: 400 | 401 | 429 | 500 | 501 | 502;
      error: string;
      description: string;
    };

/**
 * TODO(M1): replace this stub with a real call to Toss's partner API.
 *
 * Blocking items (see PLAN.md §10):
 *   1. Confirm the exact auth scheme for /oauth2/generate-token.
 *   2. Resolve JWT accessToken signature verification (JWKS vs shared secret
 *      vs treat-as-opaque).
 *   3. Decide whether /login-me is mandatory or opt-in for deriving `sub`.
 *
 * Until those are answered, this stub returns `not_implemented` so callers
 * get a clear, non-fabricated response rather than silently-fake claims.
 */
export async function verifyTossAuthorizationCode(_req: VerifyRequest): Promise<VerifyResult> {
  return {
    ok: false,
    status: 501,
    error: 'not_implemented',
    description:
      'Toss authorizationCode verification is not yet implemented. See PLAN.md §4 for the flow and §10 for open questions.',
  };
}
