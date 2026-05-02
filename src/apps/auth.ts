import { createMiddleware } from 'hono/factory';
import type { User } from '../storage/types.js';
import type { Service } from './service.js';

export interface AdminAuthOptions {
  service: Service;
  requireScope?: string;
}

declare module 'hono' {
  interface ContextVariableMap {
    user: User;
    scopes: string[];
  }
}

function unauthorized() {
  return Response.json(
    { error: 'unauthorized', error_description: 'admin auth required' },
    { status: 401 },
  );
}

function forbidden() {
  return Response.json(
    { error: 'forbidden', error_description: 'insufficient scope' },
    { status: 403 },
  );
}

export function adminAuth(opts: AdminAuthOptions) {
  return createMiddleware(async (c, next) => {
    const header = c.req.header('authorization');
    if (!header?.toLowerCase().startsWith('bearer ')) {
      return unauthorized();
    }
    const plain = header.slice('bearer '.length).trim();
    const verified = await opts.service.apiTokens.verify(plain);
    if (!verified) return unauthorized();
    if (opts.requireScope && !verified.scopes.includes(opts.requireScope)) {
      return forbidden();
    }
    c.set('user', verified.user);
    c.set('scopes', verified.scopes);
    await next();
    return undefined;
  });
}
