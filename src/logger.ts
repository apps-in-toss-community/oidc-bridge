/**
 * Backwards-compatibility re-export.
 *
 * Existing imports (`import { createLogger } from './logger.js'`) continue
 * to work unchanged. The Logger type is now the runtime-agnostic interface
 * defined in core/logger.ts — pino.Logger is an implementation detail of
 * runtime/node-logger.ts.
 */
export type { CreateLoggerOptions, Logger, LoggerMode } from './runtime/node-logger.js';
export { createLogger } from './runtime/node-logger.js';
