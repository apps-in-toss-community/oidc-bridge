/**
 * Node.js logger adapter — pino-backed implementation of the Logger port.
 *
 * This is the only file in src/ that imports pino. All production code
 * depends on the Logger interface from '../core/logger.js'.
 */
import type { Writable } from 'node:stream';
import pino, { type Logger as PinoLogger } from 'pino';
import type { Logger } from '../core/logger.js';

export type { Logger };

export const REDACT_PATHS: ReadonlyArray<string> = [
  'client_secret',
  'client_secret_hashes',
  'access_token',
  'refresh_token',
  'ait_access_token',
  'ait_refresh_token',
  'mtls_cert',
  'mtls_key',
  'mtls_cert_pem',
  'mtls_key_pem',
  'toss_access_token',
  'toss_refresh_token',
  'api_token',
  'master_key',
  'password',
  'password_hash',
  'id_token',
  'code_verifier',
  'code',
  'token',
  'req.headers.authorization',
  'res.headers.authorization',
  'res.headers["set-cookie"]',
  // Wildcard variants for nested objects.
  '*.client_secret',
  '*.access_token',
  '*.refresh_token',
  '*.ait_access_token',
  '*.ait_refresh_token',
  '*.mtls_cert',
  '*.mtls_key',
  '*.mtls_cert_pem',
  '*.mtls_key_pem',
  '*.toss_access_token',
  '*.toss_refresh_token',
  '*.api_token',
  '*.master_key',
  '*.id_token',
  '*.code_verifier',
  '*.code',
  '*.token',
  '*.password',
  '*.password_hash',
];

export type LoggerMode = 'json' | 'pretty';

export interface CreateLoggerOptions {
  mode?: LoggerMode;
  destination?: Writable;
  level?: pino.Level;
}

/**
 * Creates a pino logger that satisfies the Logger interface.
 *
 * The return type is `PinoLogger` (not just `Logger`) so callers that need
 * pino-specific features (e.g. tests) can still access them. PinoLogger
 * structurally satisfies Logger because it has all the required methods.
 */
export function createLogger(opts: CreateLoggerOptions = {}): PinoLogger {
  const mode: LoggerMode = opts.mode ?? (process.env.NODE_ENV === 'production' ? 'json' : 'pretty');
  const level: pino.Level =
    opts.level ?? (process.env.LOG_LEVEL as pino.Level | undefined) ?? 'info';

  const baseOptions: pino.LoggerOptions = {
    level,
    redact: { paths: REDACT_PATHS as string[], censor: '[Redacted]' },
    base: { service: 'oidc-bridge' },
  };

  // pino-pretty is dev-only and not safe to require in production builds.
  if (mode === 'pretty' && !opts.destination) {
    return pino({
      ...baseOptions,
      transport: {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'SYS:standard' },
      },
    });
  }

  if (opts.destination) {
    return pino(baseOptions, opts.destination);
  }
  return pino(baseOptions);
}
