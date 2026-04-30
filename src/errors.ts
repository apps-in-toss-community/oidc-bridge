export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'invalid_token'
  | 'temporarily_unavailable'
  | 'server_error';

export class OAuthError extends Error {
  constructor(
    public code: OAuthErrorCode,
    public description: string | undefined,
    public status: 400 | 401 | 403 | 500 | 502 | 503,
  ) {
    super(`${code}${description ? `: ${description}` : ''}`);
    this.name = 'OAuthError';
  }
}

export function oauthErrorBody(e: OAuthError): { error: string; error_description?: string } {
  return e.description === undefined
    ? { error: e.code }
    : { error: e.code, error_description: e.description };
}
