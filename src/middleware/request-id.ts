import type { MiddlewareHandler } from 'hono';
import type { Random } from '../core/random.js';
import { nodeRandom } from '../runtime/node-random.js';

declare module 'hono' {
  interface ContextVariableMap {
    requestId: string;
  }
}

const SAFE = /^[A-Za-z0-9_.-]+$/;

export interface RequestIdOptions {
  random?: Random;
}

export function requestId(opts: RequestIdOptions = {}): MiddlewareHandler {
  const random = opts.random ?? nodeRandom;
  return async (c, next) => {
    const inbound = c.req.header('x-request-id');
    const id = inbound && inbound.length <= 128 && SAFE.test(inbound) ? inbound : random.uuid();
    c.set('requestId', id);
    c.header('x-request-id', id);
    await next();
  };
}
