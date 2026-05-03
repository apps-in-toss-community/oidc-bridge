import { TossUpstreamError } from './adapter.js';

export class EnvelopeError extends Error {
  constructor(
    public readonly upstreamCode: string,
    public readonly upstreamMessage: string,
  ) {
    super(`Toss FAIL: ${upstreamCode}: ${upstreamMessage}`);
    this.name = 'EnvelopeError';
  }
}

export function parseEnvelope<T = unknown>(body: unknown): T {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('Toss envelope: not an object');
  }
  const env = body as { resultType?: unknown; success?: unknown; error?: unknown };
  if (env.resultType === 'SUCCESS') {
    if (env.success === undefined) {
      throw new Error('Toss envelope: SUCCESS without success body');
    }
    return env.success as T;
  }
  if (env.resultType === 'FAIL') {
    const err = env.error as { code?: unknown; message?: unknown } | undefined;
    if (!err || typeof err !== 'object') {
      throw new Error('Toss envelope: FAIL without error body');
    }
    const code = typeof err.code === 'string' ? err.code : 'UNKNOWN';
    const message = typeof err.message === 'string' ? err.message : '(no message)';
    throw new EnvelopeError(code, message);
  }
  throw new Error(`Toss envelope: unexpected resultType=${String(env.resultType)}`);
}

const INVALID_GRANT_CODES = new Set([
  'INVALID_AUTHORIZATION_CODE',
  'AUTHORIZATION_CODE_EXPIRED',
  'INVALID_REFRESH_TOKEN',
  'REFRESH_TOKEN_EXPIRED',
]);

export function mapEnvelopeError(err: unknown): TossUpstreamError {
  if (err instanceof EnvelopeError && INVALID_GRANT_CODES.has(err.upstreamCode)) {
    return new TossUpstreamError('invalid_grant', err.upstreamMessage, err);
  }
  const message = err instanceof Error ? err.message : String(err);
  return new TossUpstreamError('upstream_error', message, err);
}
