import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import type { MiddlewareHandler } from 'hono';
import type pino from 'pino';

export interface PinoHttpOpts {
  logger: pino.Logger;
  ipSalt: string;
}

function extractIp(c: { req: { header: (name: string) => string | undefined } }): string {
  const xff = c.req.header('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  return 'unknown';
}

export function pinoHttp(opts: PinoHttpOpts): MiddlewareHandler {
  return async (c, next) => {
    const start = performance.now();
    await next();
    const latencyMs = Math.round((performance.now() - start) * 1000) / 1000;
    const ip = extractIp(c);
    const ipHash = createHash('sha256').update(`${opts.ipSalt}:${ip}`).digest('hex').slice(0, 16);
    opts.logger.info({
      request_id: c.get('requestId'),
      method: c.req.method,
      path: c.req.path,
      status: c.res.status,
      latency_ms: latencyMs,
      user_agent: c.req.header('user-agent'),
      ip_hash: ipHash,
    });
  };
}
