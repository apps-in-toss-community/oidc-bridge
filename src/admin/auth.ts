import { timingSafeEqual } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';

export function adminAuth(adminToken: string): MiddlewareHandler {
  return async (c, next) => {
    const auth = c.req.header('authorization') ?? '';
    if (!auth.startsWith('Bearer ')) return c.json({ error: 'invalid_token' }, 401);
    const token = auth.slice('Bearer '.length).trim();
    const a = Buffer.from(token);
    const b = Buffer.from(adminToken);
    // timingSafeEqual requires equal-length inputs. Pad both to the longer
    // length so we always run the comparison; check length equality
    // separately.
    const len = Math.max(a.length, b.length);
    const aPad = Buffer.concat([a, Buffer.alloc(len - a.length)]);
    const bPad = Buffer.concat([b, Buffer.alloc(len - b.length)]);
    if (a.length !== b.length || !timingSafeEqual(aPad, bPad)) {
      return c.json({ error: 'invalid_token' }, 401);
    }
    await next();
  };
}
