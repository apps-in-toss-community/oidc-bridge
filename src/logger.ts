import type { Writable } from 'node:stream';
import pino, { type Logger } from 'pino';

export type LoggerMode = 'json' | 'pretty';

export interface CreateLoggerOptions {
  mode?: LoggerMode;
  destination?: Writable;
  level?: pino.Level;
}

const REDACT_PATHS = [
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

export function createLogger(opts: CreateLoggerOptions = {}): Logger {
  const mode: LoggerMode = opts.mode ?? (process.env.NODE_ENV === 'production' ? 'json' : 'pretty');
  const level: pino.Level =
    opts.level ?? (process.env.LOG_LEVEL as pino.Level | undefined) ?? 'info';

  const baseOptions: pino.LoggerOptions = {
    level,
    redact: { paths: REDACT_PATHS, censor: '[Redacted]' },
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
