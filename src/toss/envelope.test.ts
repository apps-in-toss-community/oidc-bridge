import { describe, expect, it } from 'vitest';
import { TossUpstreamError } from './adapter.js';
import { EnvelopeError, mapEnvelopeError, parseEnvelope } from './envelope.js';

describe('parseEnvelope', () => {
  it('returns success body when resultType=SUCCESS', () => {
    const body = { resultType: 'SUCCESS', success: { foo: 1 } };
    expect(parseEnvelope(body)).toEqual({ foo: 1 });
  });

  it('throws EnvelopeError with code mapped from FAIL', () => {
    const body = {
      resultType: 'FAIL',
      error: { code: 'INVALID_AUTHORIZATION_CODE', message: 'expired' },
    };
    try {
      parseEnvelope(body);
      throw new Error('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(EnvelopeError);
      const err = e as EnvelopeError;
      expect(err.upstreamCode).toBe('INVALID_AUTHORIZATION_CODE');
      expect(err.upstreamMessage).toBe('expired');
    }
  });

  it('throws on unknown resultType (treats as upstream protocol error)', () => {
    expect(() => parseEnvelope({ resultType: 'WAT' })).toThrow(/unexpected resultType/);
  });

  it('throws when SUCCESS missing success body', () => {
    expect(() => parseEnvelope({ resultType: 'SUCCESS' })).toThrow(/SUCCESS without success body/);
  });

  it('throws when FAIL missing error body', () => {
    expect(() => parseEnvelope({ resultType: 'FAIL' })).toThrow(/FAIL without error body/);
  });

  it('throws on non-object input', () => {
    expect(() => parseEnvelope(null)).toThrow(/not an object/);
    expect(() => parseEnvelope('string')).toThrow(/not an object/);
  });
});

describe('mapEnvelopeError', () => {
  it('invalid_grant for INVALID_AUTHORIZATION_CODE', () => {
    const e = new EnvelopeError('INVALID_AUTHORIZATION_CODE', 'expired or unknown');
    const mapped = mapEnvelopeError(e);
    expect(mapped).toBeInstanceOf(TossUpstreamError);
    expect(mapped.code).toBe('invalid_grant');
  });

  it('invalid_grant for INVALID_REFRESH_TOKEN', () => {
    const e = new EnvelopeError('INVALID_REFRESH_TOKEN', 'rotated');
    expect(mapEnvelopeError(e).code).toBe('invalid_grant');
  });

  it('invalid_grant for AUTHORIZATION_CODE_EXPIRED', () => {
    const e = new EnvelopeError('AUTHORIZATION_CODE_EXPIRED', 'too late');
    expect(mapEnvelopeError(e).code).toBe('invalid_grant');
  });

  it('invalid_grant for REFRESH_TOKEN_EXPIRED', () => {
    const e = new EnvelopeError('REFRESH_TOKEN_EXPIRED', 'too old');
    expect(mapEnvelopeError(e).code).toBe('invalid_grant');
  });

  it('upstream_error for unknown code', () => {
    const e = new EnvelopeError('PARTNER_QUOTA_EXCEEDED', 'try again');
    expect(mapEnvelopeError(e).code).toBe('upstream_error');
  });

  it('upstream_error for non-EnvelopeError (raw network)', () => {
    const e = new Error('connect ECONNREFUSED');
    expect(mapEnvelopeError(e).code).toBe('upstream_error');
  });
});
