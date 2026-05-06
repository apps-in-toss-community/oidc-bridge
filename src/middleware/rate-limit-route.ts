import type { MiddlewareHandler } from 'hono';
import { SlidingWindow } from './rate-limit.js';

export interface RateLimitOpts {
  ipPerMin: number;
  appPerMin: number;
  enabled: boolean;
  /** Override clock for tests. */
  now?: () => number;
}

declare module 'hono' {
  interface ContextVariableMap {
    appId?: string;
  }
}

function extractIp(headerVal: string | undefined): string {
  if (!headerVal) return 'unknown';
  const first = headerVal.split(',')[0]?.trim();
  return first || 'unknown';
}

/**
 * Per-IP + per-app sliding-window rate limiter.
 *
 * Bodies are read once via `c.req.text()` for client_id extraction; Hono's
 * internal body cache lets downstream handlers still call `parseBody()` /
 * `json()` (the cached text is re-derived on demand).
 */
export function rateLimit(opts: RateLimitOpts): MiddlewareHandler {
  if (!opts.enabled) {
    return async (_c, next) => {
      await next();
    };
  }
  const swOpts = opts.now ? { now: opts.now } : {};
  const ipWindow = new SlidingWindow({ limit: opts.ipPerMin, windowMs: 60_000, ...swOpts });
  const appWindow = new SlidingWindow({ limit: opts.appPerMin, windowMs: 60_000, ...swOpts });

  return async (c, next) => {
    const ip = extractIp(c.req.header('x-forwarded-for'));
    let appId = c.get('appId') ?? 'unknown';

    if (appId === 'unknown') {
      const ct = c.req.header('content-type') ?? '';
      const bodyCache = (c.req as unknown as { bodyCache: Record<string, unknown> }).bodyCache;
      try {
        if (ct.startsWith('application/x-www-form-urlencoded')) {
          const text = await c.req.text();
          const params = new URLSearchParams(text);
          // Pre-populate formData cache so downstream parseBody() doesn't
          // re-derive (Hono's cross-cache derive drops Content-Type and
          // breaks formData()). See node_modules/hono/dist/request.js.
          const formData = new FormData();
          for (const [k, v] of params.entries()) formData.append(k, v);
          bodyCache.formData = Promise.resolve(formData);
          const cid = params.get('client_id');
          if (cid) appId = cid;
        } else if (ct.startsWith('application/json')) {
          const text = await c.req.text();
          try {
            const j = JSON.parse(text) as { client_id?: unknown };
            bodyCache.json = Promise.resolve(j);
            if (typeof j.client_id === 'string' && j.client_id) appId = j.client_id;
          } catch {
            // Malformed JSON — keep appId='unknown'; downstream will reject.
          }
        }
      } catch {
        // Body read failure — keep appId='unknown'.
      }
    }

    if (!ipWindow.admit(ip) || !appWindow.admit(appId)) {
      c.header('retry-after', '60');
      return c.json({ error: 'rate_limited' }, 429);
    }
    await next();
  };
}
