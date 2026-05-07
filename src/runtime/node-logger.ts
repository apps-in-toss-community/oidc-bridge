/**
 * Node.js logger adapter — pino-backed implementation of the Logger port.
 *
 * This is the only file in src/ that imports pino. All production code
 * depends on the Logger interface from '../core/logger.js'.
 */
import type { Writable } from 'node:stream';
import pino, { type Logger as PinoLogger } from 'pino';
import type { Logger } from '../core/logger.js';
import { REDACT_PATHS } from '../core/logger-redact.js';

export type { Logger };
export { REDACT_PATHS };

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
