/**
 * Logger port — runtime-agnostic interface.
 *
 * Production code in src/ depends only on this interface. Concrete
 * implementations live in src/runtime/node-logger.ts (pino-backed) and
 * src/runtime/workers-logger.ts (console.log JSON-line).
 */

export interface Logger {
  info(msg: string): void;
  info(obj: Record<string, unknown>, msg?: string): void;

  warn(msg: string): void;
  warn(obj: Record<string, unknown>, msg?: string): void;

  error(msg: string): void;
  error(obj: Record<string, unknown>, msg?: string): void;

  debug(msg: string): void;
  debug(obj: Record<string, unknown>, msg?: string): void;

  fatal(msg: string): void;
  fatal(obj: Record<string, unknown>, msg?: string): void;

  child(bindings: Record<string, unknown>): Logger;
}
