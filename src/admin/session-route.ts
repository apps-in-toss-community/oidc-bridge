import { Hono } from 'hono';
import { z } from 'zod';
import { clearSessionCookie, readSessionCookie, setSessionCookie } from '../sessions/cookies.js';
import type { SessionService } from '../sessions/service.js';

const LoginBody = z.object({
  email: z.string().min(1),
  password: z.string().min(1),
});

export interface SessionRouteOpts {
  service: SessionService;
}

export function mountSessionRoute(opts: SessionRouteOpts) {
  const app = new Hono();

  app.post('/admin/login', async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'invalid_request' }, 400);
    }
    const parsed = LoginBody.safeParse(body);
    if (!parsed.success) return c.json({ error: 'invalid_request' }, 400);
    const r = await opts.service.login(parsed.data.email, parsed.data.password);
    if (r.kind === 'invalid_credentials') return c.json({ error: 'invalid_credentials' }, 401);
    if (r.kind === 'no_password_set') return c.json({ error: 'no_password_set' }, 401);
    c.header('set-cookie', setSessionCookie(r.session.id, r.session.expiresAt));
    return c.json({ ok: true });
  });

  app.post('/admin/logout', async (c) => {
    const id = readSessionCookie(c.req.header('cookie'));
    if (id) await opts.service.logout(id);
    c.header('set-cookie', clearSessionCookie());
    return c.json({ ok: true });
  });

  return app;
}
