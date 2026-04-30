import { describe, expect, it } from 'vitest';
import { OAuthError, oauthErrorBody } from './errors.js';

describe('OAuthError', () => {
  it('serializes to RFC 6749 body shape', () => {
    const e = new OAuthError('invalid_grant', 'code expired', 401);
    expect(oauthErrorBody(e)).toEqual({
      error: 'invalid_grant',
      error_description: 'code expired',
    });
    expect(e.status).toBe(401);
  });

  it('omits error_description when not provided', () => {
    const e = new OAuthError('invalid_request', undefined, 400);
    expect(oauthErrorBody(e)).toEqual({ error: 'invalid_request' });
  });
});
