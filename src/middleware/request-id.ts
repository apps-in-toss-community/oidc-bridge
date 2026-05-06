import { randomUUID } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';

declare module 'hono' {
  interface ContextVariableMap {
    requestId: string;
  }
}

const SAFE = /^[A-Za-z0-9_.-]+$/;

export function requestId(): MiddlewareHandler {
  return async (c, next) => {
    const inbound = c.req.header('x-request-id');
    const id = inbound && inbound.length <= 128 && SAFE.test(inbound) ? inbound : randomUUID();
    c.set('requestId', id);
    c.header('x-request-id', id);
    await next();
  };
}
