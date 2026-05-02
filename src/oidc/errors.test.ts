import { describe, expect, it } from 'vitest';
import { TossUpstreamError } from '../toss/adapter.js';
import { toOAuthError } from './errors.js';

describe('toOAuthError', () => {
  it('maps invalid_request', () => {
    const r = toOAuthError({ code: 'invalid_request', description: 'missing grant_type' });
    expect(r).toEqual({
      status: 400,
      body: { error: 'invalid_request', error_description: 'missing grant_type' },
    });
  });

  it('maps invalid_client to 401', () => {
    const r = toOAuthError({ code: 'invalid_client', description: 'unknown client_id' });
    expect(r.status).toBe(401);
    expect(r.body.error).toBe('invalid_client');
  });

  it('maps invalid_grant to 401', () => {
    const r = toOAuthError({ code: 'invalid_grant', description: 'rejected by upstream' });
    expect(r.status).toBe(401);
  });

  it('maps TossUpstreamError(invalid_grant)', () => {
    const e = new TossUpstreamError('invalid_grant', 'fail');
    const r = toOAuthError(e);
    expect(r).toEqual({ status: 401, body: { error: 'invalid_grant', error_description: 'fail' } });
  });

  it('maps TossUpstreamError(upstream_error) to 502', () => {
    const e = new TossUpstreamError('upstream_error', 'net');
    const r = toOAuthError(e);
    expect(r.status).toBe(502);
    expect(r.body.error).toBe('upstream_error');
  });

  it('falls back to server_error 500 for unknown', () => {
    const r = toOAuthError(new Error('boom'));
    expect(r).toEqual({
      status: 500,
      body: { error: 'server_error', error_description: 'unexpected server error' },
    });
  });
});
