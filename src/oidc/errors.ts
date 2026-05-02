import { TossUpstreamError } from '../toss/adapter.js';

export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unsupported_grant_type'
  | 'app_not_verified'
  | 'upstream_error'
  | 'server_misconfigured'
  | 'server_unavailable'
  | 'server_error';

export interface OAuthErrorInput {
  code: OAuthErrorCode;
  description: string;
}

export interface OAuthErrorResponse {
  status: number;
  body: { error: OAuthErrorCode; error_description: string };
}

const STATUS: Record<OAuthErrorCode, number> = {
  invalid_request: 400,
  invalid_client: 401,
  invalid_grant: 401,
  unsupported_grant_type: 400,
  app_not_verified: 403,
  upstream_error: 502,
  server_misconfigured: 500,
  server_unavailable: 500,
  server_error: 500,
};

export function toOAuthError(input: OAuthErrorInput | Error): OAuthErrorResponse {
  if (input instanceof TossUpstreamError) {
    return {
      status: STATUS[input.code],
      body: { error: input.code, error_description: input.message },
    };
  }
  if (input instanceof Error) {
    return {
      status: 500,
      body: { error: 'server_error', error_description: 'unexpected server error' },
    };
  }
  return {
    status: STATUS[input.code],
    body: { error: input.code, error_description: input.description },
  };
}
