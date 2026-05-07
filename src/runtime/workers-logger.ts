/**
 * Cloudflare Workers logger adapter — JSON-line console.log implementation.
 *
 * Uses the same REDACT_PATHS list as the Node/pino logger, applied
 * recursively at every object depth. Output format matches pino's JSON
 * shape (msg, time, level as string, service in base bindings).
 */
import type { Logger } from '../core/logger.js';
import { REDACT_PATHS } from '../core/logger-redact.js';

export interface WorkersLoggerOptions {
  level?: 'debug' | 'info' | 'warn' | 'error' | 'fatal';
  base?: Record<string, unknown>;
  /** Injectable for tests — defaults to globalThis.console. */
  console?: { log: (line: string) => void };
}

const LEVEL_ORDER = ['debug', 'info', 'warn', 'error', 'fatal'] as const;
type Level = (typeof LEVEL_ORDER)[number];

// Numeric level codes matching pino's convention (for parity of JSON shape).
const LEVEL_NUMS: Record<Level, number> = {
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
};

/**
 * Builds a Set of bare key names from REDACT_PATHS.
 *
 * Rules:
 * - Simple paths like `client_secret` → add key directly.
 * - Wildcard paths like `*.client_secret` → strip `*.` prefix, add key.
 * - Dotted paths like `req.headers.authorization` → add the leaf segment only
 *   (`authorization`). This is a conservative approximation that keeps the
 *   Workers impl in sync with the redact semantics for the most common cases.
 * - Special bracket paths like `res.headers["set-cookie"]` → extract leaf
 *   key name (`set-cookie`).
 */
function buildRedactKeys(): ReadonlySet<string> {
  const keys = new Set<string>();
  for (const path of REDACT_PATHS) {
    if (path.startsWith('*.')) {
      keys.add(path.slice(2));
    } else if (path.includes('[')) {
      // e.g. `res.headers["set-cookie"]`
      const match = /\["([^"]+)"\]$/.exec(path);
      if (match?.[1]) keys.add(match[1]);
    } else if (path.includes('.')) {
      // e.g. `req.headers.authorization` → redact `authorization` at any depth
      const parts = path.split('.');
      const leaf = parts[parts.length - 1];
      if (leaf) keys.add(leaf);
    } else {
      keys.add(path);
    }
  }
  return keys;
}

const REDACT_KEYS = buildRedactKeys();

/** Recursively redact any object key that appears in the redact set. */
function deepRedact(value: unknown, keys: ReadonlySet<string>): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => deepRedact(item, keys));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = keys.has(k) ? '[Redacted]' : deepRedact(v, keys);
  }
  return out;
}

export function createWorkersLogger(opts: WorkersLoggerOptions = {}): Logger {
  const minLevel: Level = opts.level ?? 'info';
  const base: Record<string, unknown> = opts.base ?? { service: 'oidc-bridge' };
  const con = opts.console ?? { log: (s: string) => console.log(s) };
  const minIdx = LEVEL_ORDER.indexOf(minLevel);

  function shouldEmit(lvl: Level): boolean {
    return LEVEL_ORDER.indexOf(lvl) >= minIdx;
  }

  function emit(lvl: Level, arg1: string | Record<string, unknown>, arg2?: string): void {
    if (!shouldEmit(lvl)) return;
    let obj: Record<string, unknown>;
    let msg: string;
    if (typeof arg1 === 'string') {
      obj = {};
      msg = arg1;
    } else {
      obj = arg1;
      msg = arg2 ?? '';
    }
    const redacted = deepRedact(obj, REDACT_KEYS) as Record<string, unknown>;
    const line = JSON.stringify({
      level: LEVEL_NUMS[lvl],
      time: Date.now(),
      ...base,
      ...redacted,
      msg,
    });
    con.log(line);
  }

  function child(bindings: Record<string, unknown>): Logger {
    return createWorkersLogger({
      level: minLevel,
      base: { ...base, ...bindings },
      console: con,
    });
  }

  return {
    info: (arg1: string | Record<string, unknown>, arg2?: string) =>
      emit('info', arg1 as string, arg2),
    warn: (arg1: string | Record<string, unknown>, arg2?: string) =>
      emit('warn', arg1 as string, arg2),
    error: (arg1: string | Record<string, unknown>, arg2?: string) =>
      emit('error', arg1 as string, arg2),
    debug: (arg1: string | Record<string, unknown>, arg2?: string) =>
      emit('debug', arg1 as string, arg2),
    fatal: (arg1: string | Record<string, unknown>, arg2?: string) =>
      emit('fatal', arg1 as string, arg2),
    child,
  };
}
