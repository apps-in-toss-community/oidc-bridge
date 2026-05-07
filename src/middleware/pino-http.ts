import { performance } from 'node:perf_hooks';
import type { MiddlewareHandler } from 'hono';
import type pino from 'pino';
import { fromUtf8, toHex } from '../core/bytes.js';
import type { Digest } from '../core/digest.js';
import { nodeDigest } from '../runtime/node-digest.js';

export interface PinoHttpOpts {
  logger: pino.Logger;
  ipSalt: string;
  digest?: Digest;
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
  const digest = opts.digest ?? nodeDigest;
  return async (c, next) => {
    const start = performance.now();
    await next();
    const latencyMs = Math.round((performance.now() - start) * 1000) / 1000;
    const ip = extractIp(c);
    const ipBytes = fromUtf8(`${opts.ipSalt}:${ip}`);
    const ipHashFull = toHex(await digest.digest('SHA-256', ipBytes));
    const ipHash = ipHashFull.slice(0, 16);
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
