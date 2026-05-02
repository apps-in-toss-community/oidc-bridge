# oidc-bridge zero-code mode — Phase 8: status page + rate-limit + observability

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three operator-facing concerns shipped together because they all need request middleware: (1) `GET /status` HTML page (no auth) showing version / build SHA / DB / master-key / last-successful-`/healthz`; (2) sliding-window rate limits per-IP on `/oidc/*` and per-app across all OIDC endpoints; (3) pino structured logs with `x-request-id` correlation, plus optional OpenTelemetry HTTP exporter behind `OTEL_ENABLED=1`.

**Architecture:** A new `src/middleware/` directory owns three middleware factories: `requestId`, `rateLimit`, `pinoHttp`. `/status` reuses Phase 7's probe shape (`{ name, state, detail }`) so the bridge runs the same probes the CLI does — no duplicate logic. Rate limits are in-memory, per-instance (a deliberate trade for self-host simplicity); a single sliding window class is shared between IP and app keys. OTel is **opt-in** via `OTEL_ENABLED=1`; when off, no OTel module is imported (lazy `await import(...)`), so self-host installs that don't want it pay zero startup cost.

**Tech stack:** TypeScript ESM strict, `hono`, `pino` + `pino-http`-style request logging hand-rolled (no new dep), `node:crypto.randomUUID`, `vitest`. New dev dep: none. New optional prod dep (lazy-loaded): `@opentelemetry/sdk-node` + `@opentelemetry/auto-instrumentations-node` — added under `optionalDependencies` so `pnpm install` does not require them in self-host installs that don't enable OTel.

---

## Universal invariants (apply to every task)

1. **TDD.** Failing test → minimal code → green → commit.
2. **Frequent commits.** Each red→green cycle is a commit.
3. **No premature abstractions.** No metric registry abstraction beyond what OTel provides; no rate-limit storage backend interface (in-memory only, documented).
4. **No PII / secrets in logs.** Request log line never includes the raw body. Only: method, path, status, latency_ms, request_id, ip (sha256-hashed), user_agent.
5. **Bridge never spontaneously calls Toss.** Status page does not call Toss. Doctor's Toss probe is **not** included in the runtime status page (it would need an mTLS handshake on every status hit; instead the page links to the most recent doctor run via a separate sysadmin path).
6. **Toss `refresh_token` never leaves the sealed wrapper.** Unaffected.
7. **Public clients use `Origin`, never `client_secret`.** Unaffected.
8. **mTLS material never returns from any GET.** `/status` does not show cert/key contents under any circumstance. The status item for "mtls registered apps" shows only a count, not bytes.
9. **Cloud-agnostic.** OTel exporter target is configured by env (`OTEL_EXPORTER_OTLP_ENDPOINT`); the bridge does not assume Cloud Trace or any specific backend.
10. **Self-host first-class.** All three features (status, rate limit, structured logs) work identically in self-host and Cloud Run. OTel is opt-in everywhere.
11. **Bite-sized tasks.** Each step ≈2–5 minutes.
12. **Lint + typecheck + test pass on every commit.**

## Files this phase touches

```
src/
  middleware/
    request-id.ts                # NEW — set/propagate x-request-id; expose c.var.requestId
    request-id.test.ts           # NEW
    pino-http.ts                 # NEW — emit one request log line per response
    pino-http.test.ts            # NEW
    rate-limit.ts                # NEW — sliding-window counter, generic key + limit
    rate-limit.test.ts           # NEW — boundary + reset
    rate-limit-route.ts          # NEW — per-IP + per-app middleware wired into routes
    rate-limit-route.test.ts     # NEW
  status/
    route.ts                     # NEW — GET /status (HTML for TTY-y clients, JSON otherwise)
    route.test.ts                # NEW
    probes.ts                    # NEW — runtime version of doctor probes (DB, master-key, jwks, last-healthz)
    probes.test.ts               # NEW
    last-healthz.ts              # NEW — in-memory timestamp of last successful /healthz request
    last-healthz.test.ts         # NEW
  observability/
    otel.ts                      # NEW — lazy-init OpenTelemetry SDK if OTEL_ENABLED=1
    otel.test.ts                 # NEW — env off path (no import side effects)
  app.ts                         # MODIFY — wire middleware in correct order
  server.ts                      # MODIFY — start otel before buildApp; capture build sha at boot
  config.ts                      # MODIFY — read RATE_LIMIT_*, OTEL_*, BRIDGE_BUILD_SHA
package.json                     # MODIFY — optionalDependencies: @opentelemetry/sdk-node + auto-instrumentations
docs/
  RUNBOOK.md                     # MODIFY — section "rate limits" + "structured logs" + "OTel"
```

## Pre-flight (do this once before Task 1)

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-08 origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

If any check fails, stop. Phases 0–7 are not green; fix that before continuing.

This phase depends on:

- Phase 7's `ProbeItem` / `ProbeReport` shape (re-used for `/status`).
- Phase 7's `runDbProbe`, `runMasterKeyProbe`, `runJwksProbe` (re-used unchanged for the runtime probe set).
- Phase 0's pino logger (extended in this phase to be a per-request child).

---

## Task 1: `requestId` middleware

**Files:**
- Create: `src/middleware/request-id.ts`
- Test: `src/middleware/request-id.test.ts`

Honors an inbound `X-Request-Id` header if present (max 128 chars, must match `^[A-Za-z0-9_.\-]+$` to prevent log injection). Otherwise generates a fresh UUID v4. Sets `c.set('requestId', id)` and adds `X-Request-Id` to the response.

- [ ] **Step 1: Failing test**

```ts
// src/middleware/request-id.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { requestId } from './request-id.js';

describe('requestId middleware', () => {
  it('uses inbound X-Request-Id when valid', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId')));
    const r = await app.request('/', { headers: { 'x-request-id': 'abc.123' } });
    expect(await r.text()).toBe('abc.123');
    expect(r.headers.get('x-request-id')).toBe('abc.123');
  });

  it('generates UUID when no inbound header', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId')));
    const r = await app.request('/');
    const echoed = await r.text();
    expect(echoed).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(r.headers.get('x-request-id')).toBe(echoed);
  });

  it('rejects malformed inbound id (would allow log injection)', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId')));
    const r = await app.request('/', { headers: { 'x-request-id': 'a b\nc' } });
    const echoed = await r.text();
    // Should have replaced with a fresh UUID, not echoed back the injection vector.
    expect(echoed).not.toBe('a b\nc');
    expect(echoed).toMatch(/^[0-9a-f-]+$/);
  });

  it('rejects inbound id over 128 chars', async () => {
    const app = new Hono();
    app.use('*', requestId());
    app.get('/', (c) => c.text(c.get('requestId')));
    const r = await app.request('/', { headers: { 'x-request-id': 'a'.repeat(129) } });
    const echoed = await r.text();
    expect(echoed).not.toBe('a'.repeat(129));
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/middleware/request-id.ts
import { randomUUID } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';

const SAFE = /^[A-Za-z0-9_.\-]+$/;

export function requestId(): MiddlewareHandler {
  return async (c, next) => {
    const inbound = c.req.header('x-request-id');
    const id = inbound && inbound.length <= 128 && SAFE.test(inbound) ? inbound : randomUUID();
    c.set('requestId', id);
    c.header('x-request-id', id);
    await next();
  };
}
```

Hono's context types extend automatically when you call `c.set('requestId', ...)`; if your project uses a stricter Hono context typing (`Hono<{ Variables: ... }>`), declare `requestId: string` in the Variables type so `c.get('requestId')` is typed.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/middleware/request-id.ts src/middleware/request-id.test.ts
git commit -m "feat(middleware): requestId honors X-Request-Id with injection guard"
```

---

## Task 2: `pinoHttp` middleware (one log line per response)

**Files:**
- Create: `src/middleware/pino-http.ts`
- Test: `src/middleware/pino-http.test.ts`

Emits exactly one log line per request, after the response is sent. Fields: `level`, `time`, `request_id`, `method`, `path`, `status`, `latency_ms`, `user_agent`, `ip_hash`. The IP is sha256-hashed with a per-instance salt (env: `IP_HASH_SALT`, default a process-startup random) so logs don't expose raw IPs.

- [ ] **Step 1: Failing test**

```ts
// src/middleware/pino-http.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import pino from 'pino';
import { pinoHttp } from './pino-http.js';
import { requestId } from './request-id.js';

function captureLogger(): { logger: pino.Logger; logs: string[] } {
  const logs: string[] = [];
  const stream = { write: (s: string) => { logs.push(s); return true; } };
  const logger = pino({}, stream as never);
  return { logger, logs };
}

describe('pinoHttp', () => {
  it('emits one line per request with required fields', async () => {
    const { logger, logs } = captureLogger();
    const app = new Hono();
    app.use('*', requestId());
    app.use('*', pinoHttp({ logger, ipSalt: 'salt' }));
    app.get('/x', (c) => c.text('ok'));
    await app.request('/x', { headers: { 'user-agent': 'test/1.0' } });
    const line = JSON.parse(logs[0]!);
    expect(line.method).toBe('GET');
    expect(line.path).toBe('/x');
    expect(line.status).toBe(200);
    expect(typeof line.latency_ms).toBe('number');
    expect(line.user_agent).toBe('test/1.0');
    expect(typeof line.request_id).toBe('string');
    expect(line.ip_hash).toMatch(/^[0-9a-f]{16}$/); // 8 bytes hex
  });

  it('does not log the request body', async () => {
    const { logger, logs } = captureLogger();
    const app = new Hono();
    app.use('*', requestId());
    app.use('*', pinoHttp({ logger, ipSalt: 'salt' }));
    app.post('/x', async (c) => { await c.req.text(); return c.text('ok'); });
    await app.request('/x', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'SUPER_SECRET_VALUE',
    });
    expect(logs[0]).not.toContain('SUPER_SECRET_VALUE');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/middleware/pino-http.ts
import { createHash } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';
import type pino from 'pino';

export interface PinoHttpOpts {
  logger: pino.Logger;
  ipSalt: string;
}

export function pinoHttp(opts: PinoHttpOpts): MiddlewareHandler {
  return async (c, next) => {
    const start = performance.now();
    await next();
    const latencyMs = Math.round((performance.now() - start) * 1000) / 1000;
    const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? c.env?.remoteAddr ?? 'unknown';
    const ipHash = createHash('sha256').update(opts.ipSalt + ':' + ip).digest('hex').slice(0, 16);
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
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/middleware/pino-http.ts src/middleware/pino-http.test.ts
git commit -m "feat(middleware): pino-http emits one structured log line per request"
```

---

## Task 3: Sliding-window rate-limit counter

**Files:**
- Create: `src/middleware/rate-limit.ts`
- Test: `src/middleware/rate-limit.test.ts`

A class `SlidingWindow(limit, windowMs)` that admits-or-rejects-and-counts requests per key. The window is a single-bucket approximation: it tracks the count for the current window plus the count for the previous window; the effective count is a weighted blend (Cloudflare-style). Memory is one entry per active key per window; we sweep stale keys on every Nth call to keep the map bounded.

- [ ] **Step 1: Failing test**

```ts
// src/middleware/rate-limit.test.ts
import { describe, it, expect, vi } from 'vitest';
import { SlidingWindow } from './rate-limit.js';

describe('SlidingWindow', () => {
  it('admits up to limit within a window', () => {
    vi.setSystemTime(0);
    const sw = new SlidingWindow({ limit: 3, windowMs: 60_000 });
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
  });

  it('separate keys are independent', () => {
    vi.setSystemTime(0);
    const sw = new SlidingWindow({ limit: 1, windowMs: 60_000 });
    expect(sw.admit('a')).toBe(true);
    expect(sw.admit('b')).toBe(true);
    expect(sw.admit('a')).toBe(false);
    expect(sw.admit('b')).toBe(false);
  });

  it('window slides as time advances', () => {
    vi.setSystemTime(0);
    const sw = new SlidingWindow({ limit: 2, windowMs: 60_000 });
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
    // Halfway into the next window — previous count weighted at 50%, current at 0%.
    // Effective = 2 * 0.5 + 0 = 1, room for 1 more.
    vi.setSystemTime(90_000);
    expect(sw.admit('k')).toBe(true);
    expect(sw.admit('k')).toBe(false);
  });

  it('eventually evicts stale keys', () => {
    vi.setSystemTime(0);
    const sw = new SlidingWindow({ limit: 1, windowMs: 60_000 });
    for (let i = 0; i < 1000; i++) sw.admit(`k${i}`);
    // Two windows later, all old keys should be sweep-eligible.
    vi.setSystemTime(180_000);
    sw.admit('trigger-sweep');
    expect(sw.size()).toBeLessThan(1000);
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/middleware/rate-limit.ts
export interface SlidingWindowOpts {
  limit: number;
  windowMs: number;
  now?: () => number;
}

interface Bucket {
  current: number;
  previous: number;
  windowStart: number;
}

export class SlidingWindow {
  private readonly buckets = new Map<string, Bucket>();
  private readonly now: () => number;
  private opCount = 0;

  constructor(private readonly opts: SlidingWindowOpts) {
    this.now = opts.now ?? Date.now;
  }

  admit(key: string): boolean {
    this.maybeSweep();
    const t = this.now();
    const wstart = Math.floor(t / this.opts.windowMs) * this.opts.windowMs;
    let b = this.buckets.get(key);
    if (!b) {
      b = { current: 0, previous: 0, windowStart: wstart };
      this.buckets.set(key, b);
    } else if (b.windowStart !== wstart) {
      const gap = (wstart - b.windowStart) / this.opts.windowMs;
      if (gap === 1) {
        b.previous = b.current;
        b.current = 0;
      } else {
        b.previous = 0;
        b.current = 0;
      }
      b.windowStart = wstart;
    }
    const intoWindow = (t - wstart) / this.opts.windowMs;
    const effective = b.previous * (1 - intoWindow) + b.current;
    if (effective >= this.opts.limit) return false;
    b.current += 1;
    return true;
  }

  size(): number {
    return this.buckets.size;
  }

  private maybeSweep(): void {
    this.opCount += 1;
    if (this.opCount % 1000 !== 0) return;
    const t = this.now();
    const cutoff = t - 2 * this.opts.windowMs;
    for (const [k, b] of this.buckets) {
      if (b.windowStart < cutoff) this.buckets.delete(k);
    }
  }
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/middleware/rate-limit.ts src/middleware/rate-limit.test.ts
git commit -m "feat(middleware): sliding-window rate-limit counter"
```

---

## Task 4: `rateLimit` route middleware (per-IP + per-app)

**Files:**
- Create: `src/middleware/rate-limit-route.ts`
- Test: `src/middleware/rate-limit-route.test.ts`

Two `SlidingWindow` instances at module scope: `ipWindow` and `appWindow`. The middleware:

1. Resolves the IP from `x-forwarded-for` (first hop) or socket.
2. Resolves the appId from the request: prefers `c.var.appId` if a route handler set it, else extracts from form/JSON body's `client_id`, else `unknown`.
3. Calls both windows. On either rejection, returns `429 { error: 'rate_limited' }` with `Retry-After: <windowMs/1000>`.

Limits come from env (`RATE_LIMIT_IP_PER_MIN`, default `60`; `RATE_LIMIT_APP_PER_MIN`, default `600`); both default-on with `RATE_LIMIT_ENABLED=true`. Self-host docs (Phase 9) note that operators behind a single shared NAT should set `RATE_LIMIT_IP_PER_MIN` higher or set `RATE_LIMIT_ENABLED=false`.

- [ ] **Step 1: Failing test**

```ts
// src/middleware/rate-limit-route.test.ts
import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';
import { rateLimit } from './rate-limit-route.js';

describe('rateLimit middleware', () => {
  it('allows up to ip limit then 429', async () => {
    vi.setSystemTime(0);
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 2, appPerMin: 1000, enabled: true }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = () => app.request('/oidc/token', {
      method: 'POST',
      headers: { 'x-forwarded-for': '1.2.3.4' },
      body: 'client_id=app_a',
    });
    expect((await fire()).status).toBe(200);
    expect((await fire()).status).toBe(200);
    const r = await fire();
    expect(r.status).toBe(429);
    expect(await r.json()).toMatchObject({ error: 'rate_limited' });
    expect(r.headers.get('retry-after')).toBe('60');
  });

  it('returns 429 when app limit exceeded even if IP limit ok', async () => {
    vi.setSystemTime(0);
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1000, appPerMin: 1, enabled: true }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = (ip: string) => app.request('/oidc/token', {
      method: 'POST',
      headers: { 'x-forwarded-for': ip },
      body: 'client_id=app_a',
    });
    expect((await fire('1.1.1.1')).status).toBe(200);
    expect((await fire('2.2.2.2')).status).toBe(429); // different IP, same app, app limit hit
  });

  it('disabled by env: never rate-limits', async () => {
    vi.setSystemTime(0);
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1, appPerMin: 1, enabled: false }));
    app.post('/oidc/token', (c) => c.text('ok'));
    const fire = () => app.request('/oidc/token', { method: 'POST', headers: { 'x-forwarded-for': '1.1.1.1' } });
    for (let i = 0; i < 5; i++) {
      expect((await fire()).status).toBe(200);
    }
  });

  it('falls back to "unknown" appId when body has no client_id', async () => {
    vi.setSystemTime(0);
    const app = new Hono();
    app.use('*', rateLimit({ ipPerMin: 1000, appPerMin: 1, enabled: true }));
    app.get('/oidc/userinfo', (c) => c.text('ok'));
    const fire = (ip: string) => app.request('/oidc/userinfo', { headers: { 'x-forwarded-for': ip } });
    expect((await fire('1.1.1.1')).status).toBe(200);
    expect((await fire('2.2.2.2')).status).toBe(429); // both share appId="unknown"
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/middleware/rate-limit-route.ts
import type { MiddlewareHandler } from 'hono';
import { SlidingWindow } from './rate-limit.js';

export interface RateLimitOpts {
  ipPerMin: number;
  appPerMin: number;
  enabled: boolean;
}

export function rateLimit(opts: RateLimitOpts): MiddlewareHandler {
  if (!opts.enabled) {
    return async (_c, next) => { await next(); };
  }
  const ipWindow = new SlidingWindow({ limit: opts.ipPerMin, windowMs: 60_000 });
  const appWindow = new SlidingWindow({ limit: opts.appPerMin, windowMs: 60_000 });
  return async (c, next) => {
    const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    let appId = (c.get('appId') as string | undefined) ?? 'unknown';
    if (appId === 'unknown') {
      // Best-effort body peek for OAuth requests (form or JSON).
      try {
        const ct = c.req.header('content-type') ?? '';
        if (ct.startsWith('application/x-www-form-urlencoded')) {
          const text = await c.req.text();
          c.req.bodyCache = c.req.bodyCache ?? {};
          (c.req.bodyCache as { text?: string }).text = text; // restore for downstream
          const params = new URLSearchParams(text);
          if (params.get('client_id')) appId = params.get('client_id')!;
        } else if (ct.startsWith('application/json')) {
          const text = await c.req.text();
          (c.req.bodyCache as { text?: string }).text = text;
          try {
            const j = JSON.parse(text) as { client_id?: string };
            if (j.client_id) appId = j.client_id;
          } catch { /* malformed JSON — leave appId=unknown */ }
        }
      } catch { /* leave appId=unknown */ }
    }
    if (!ipWindow.admit(ip) || !appWindow.admit(appId)) {
      c.header('retry-after', '60');
      return c.json({ error: 'rate_limited' }, 429);
    }
    await next();
  };
}
```

The body-peek-and-restore pattern is the awkward part. If Hono's body cache shape differs from `bodyCache.text`, adapt. The intent: read the body once for rate-limit lookup without preventing the route handler from reading it again.

If Hono does not expose a public body-cache API on the version installed, an alternative is: take the body text, expose it via `c.set('rawBody', text)`, and have downstream OIDC routes read `c.var.rawBody` instead of `c.req.text()`. Pick whichever path is cleaner on the actual Hono version; pin the choice in code comments.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/middleware/rate-limit-route.ts src/middleware/rate-limit-route.test.ts
git commit -m "feat(middleware): per-IP + per-app sliding-window rate limit"
```

---

## Task 5: `last-healthz` recorder + probe

**Files:**
- Create: `src/status/last-healthz.ts`
- Test: `src/status/last-healthz.test.ts`

A tiny in-memory ring of size 1: the timestamp of the last successful `/healthz` response. Wired into the existing `/healthz` handler from Phase 0 with a one-line side effect. Read by `/status` and the runtime probe.

- [ ] **Step 1: Failing test**

```ts
// src/status/last-healthz.test.ts
import { describe, it, expect } from 'vitest';
import { recordHealthz, getLastHealthz, resetLastHealthz } from './last-healthz.js';

describe('last-healthz', () => {
  it('starts as null', () => {
    resetLastHealthz();
    expect(getLastHealthz()).toBeNull();
  });

  it('records and returns most recent timestamp', () => {
    resetLastHealthz();
    recordHealthz(new Date('2026-05-01T00:00:00Z'));
    expect(getLastHealthz()?.toISOString()).toBe('2026-05-01T00:00:00.000Z');
    recordHealthz(new Date('2026-05-01T00:01:00Z'));
    expect(getLastHealthz()?.toISOString()).toBe('2026-05-01T00:01:00.000Z');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/status/last-healthz.ts
let last: Date | null = null;

export function recordHealthz(at: Date = new Date()): void {
  last = at;
}

export function getLastHealthz(): Date | null {
  return last;
}

export function resetLastHealthz(): void {
  last = null;
}
```

In `src/healthz-route.ts` (Phase 0), add `recordHealthz()` to the existing handler:

```ts
import { recordHealthz } from './status/last-healthz.js';

app.get('/healthz', (c) => {
  recordHealthz();
  return c.json({ status: 'ok' });
});
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/status/last-healthz.ts src/status/last-healthz.test.ts src/healthz-route.ts
git commit -m "feat(status): record last-healthz timestamp"
```

---

## Task 6: Runtime status probes (re-use Phase 7 probe shape)

**Files:**
- Create: `src/status/probes.ts`
- Test: `src/status/probes.test.ts`

The runtime probes are a strict subset of doctor's: `db`, `master-key`, `jwks`, `last-healthz`. No env probe (the running process has already validated env at startup). No Toss probe (it would mTLS-handshake on every status hit).

- [ ] **Step 1: Failing test**

```ts
// src/status/probes.test.ts
import { describe, it, expect } from 'vitest';
import { runStatusProbes } from './probes.js';
import { recordHealthz, resetLastHealthz } from './last-healthz.js';

describe('runStatusProbes', () => {
  it('returns at least four named probes', async () => {
    resetLastHealthz();
    recordHealthz();
    const items = await runStatusProbes({
      dbUrl: 'sqlite::memory:',
      masterKeyProvider: 'env',
      masterKeyDir: undefined,
      activeKid: 'k1',
      signingKeys: { k1: '-----BEGIN PRIVATE KEY-----\nzz\n-----END PRIVATE KEY-----\n' },
    });
    const names = items.map((i) => i.name).sort();
    expect(names).toEqual(['db', 'jwks', 'last-healthz', 'master-key']);
  });

  it('last-healthz is yellow when never hit', async () => {
    resetLastHealthz();
    const items = await runStatusProbes({ dbUrl: 'sqlite::memory:', masterKeyProvider: 'env', masterKeyDir: undefined, activeKid: 'k1', signingKeys: { k1: 'PEM' } });
    expect(items.find((i) => i.name === 'last-healthz')?.state).toBe('yellow');
  });

  it('last-healthz is green when recent', async () => {
    resetLastHealthz();
    recordHealthz();
    const items = await runStatusProbes({ dbUrl: 'sqlite::memory:', masterKeyProvider: 'env', masterKeyDir: undefined, activeKid: 'k1', signingKeys: { k1: 'PEM' } });
    expect(items.find((i) => i.name === 'last-healthz')?.state).toBe('green');
  });

  it('last-healthz is red when stale (>5 min)', async () => {
    resetLastHealthz();
    recordHealthz(new Date(Date.now() - 6 * 60_000));
    const items = await runStatusProbes({ dbUrl: 'sqlite::memory:', masterKeyProvider: 'env', masterKeyDir: undefined, activeKid: 'k1', signingKeys: { k1: 'PEM' } });
    expect(items.find((i) => i.name === 'last-healthz')?.state).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/status/probes.ts
import type { ProbeItem } from '../../cli/output.js';
import { runDbProbe } from '../../cli/commands/doctor-probes/db-probe.js';
import { runMasterKeyProbe } from '../../cli/commands/doctor-probes/master-key-probe.js';
import { runJwksProbe } from '../../cli/commands/doctor-probes/jwks-probe.js';
import { getLastHealthz } from './last-healthz.js';

export interface StatusProbeOpts {
  dbUrl: string;
  masterKeyProvider: 'env' | 'file' | 'gcpsm';
  masterKeyDir?: string;
  activeKid: string;
  signingKeys: Record<string, string>;
}

export async function runStatusProbes(opts: StatusProbeOpts): Promise<ProbeItem[]> {
  const items: ProbeItem[] = [];
  items.push(await runDbProbe({ dbUrl: opts.dbUrl }));
  items.push(await runMasterKeyProbe({ provider: opts.masterKeyProvider, masterKeyDir: opts.masterKeyDir, version: 1 }));
  items.push(await runJwksProbe({ activeKid: opts.activeKid, signingKeys: opts.signingKeys }));
  items.push(probeLastHealthz());
  return items;
}

function probeLastHealthz(): ProbeItem {
  const last = getLastHealthz();
  if (!last) return { name: 'last-healthz', state: 'yellow', detail: 'never received a /healthz hit' };
  const ageMs = Date.now() - last.getTime();
  if (ageMs > 5 * 60_000) return { name: 'last-healthz', state: 'red', detail: `stale: ${Math.round(ageMs / 1000)}s ago` };
  return { name: 'last-healthz', state: 'green', detail: `ok: ${Math.round(ageMs / 1000)}s ago` };
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/status/probes.ts src/status/probes.test.ts
git commit -m "feat(status): runtime probes (db/master-key/jwks/last-healthz)"
```

---

## Task 7: `/status` route (HTML + JSON content-negotiated)

**Files:**
- Create: `src/status/route.ts`
- Test: `src/status/route.test.ts`

Honors `Accept: application/json` (and `?format=json`) for machine-readable output; otherwise returns a small HTML page with a colored table. No auth — the page deliberately exposes operational state, not secrets. The version + build SHA come from env (`BRIDGE_VERSION`, `BRIDGE_BUILD_SHA`).

- [ ] **Step 1: Failing test**

```ts
// src/status/route.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { mountStatusRoute } from './route.js';

const probesStub = async () => [
  { name: 'db', state: 'green' as const, detail: 'ok' },
  { name: 'jwks', state: 'green' as const, detail: 'ok' },
];

describe('/status route', () => {
  it('returns JSON when Accept: application/json', async () => {
    const app = new Hono();
    app.route('/', mountStatusRoute({
      version: '1.2.3',
      buildSha: 'abc1234',
      probes: probesStub,
    }));
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('application/json');
    const j = await r.json();
    expect(j.version).toBe('1.2.3');
    expect(j.build_sha).toBe('abc1234');
    expect(j.status).toBe('green');
    expect(j.items).toHaveLength(2);
  });

  it('returns HTML by default', async () => {
    const app = new Hono();
    app.route('/', mountStatusRoute({
      version: '1.2.3',
      buildSha: 'abc1234',
      probes: probesStub,
    }));
    const r = await app.request('/status');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/html');
    const body = await r.text();
    expect(body).toContain('1.2.3');
    expect(body).toContain('abc1234');
    expect(body).toContain('db');
    expect(body).toContain('jwks');
  });

  it('?format=json forces JSON', async () => {
    const app = new Hono();
    app.route('/', mountStatusRoute({
      version: '1.2.3',
      buildSha: 'abc1234',
      probes: probesStub,
    }));
    const r = await app.request('/status?format=json');
    expect(r.headers.get('content-type')).toContain('application/json');
  });

  it('overall is worst-of', async () => {
    const probes = async () => [
      { name: 'db', state: 'green' as const, detail: 'ok' },
      { name: 'jwks', state: 'red' as const, detail: 'broken' },
    ];
    const app = new Hono();
    app.route('/', mountStatusRoute({ version: '1', buildSha: 'a', probes }));
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    const j = await r.json();
    expect(j.status).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/status/route.ts
import { Hono } from 'hono';
import type { ProbeItem, ProbeState } from '../../cli/output.js';

export interface StatusRouteOpts {
  version: string;
  buildSha: string;
  probes: () => Promise<ProbeItem[]>;
}

const RANK: Record<ProbeState, number> = { green: 0, yellow: 1, red: 2 };

function worstOf(items: ProbeItem[]): ProbeState {
  let s: ProbeState = 'green';
  for (const i of items) if (RANK[i.state] > RANK[s]) s = i.state;
  return s;
}

const COLOR: Record<ProbeState, string> = { green: '#1a7f37', yellow: '#bf8700', red: '#cf222e' };

function renderHtml(opts: { version: string; buildSha: string; status: ProbeState; items: ProbeItem[] }): string {
  const rows = opts.items.map((i) => `
    <tr>
      <td>${escapeHtml(i.name)}</td>
      <td><span style="color:${COLOR[i.state]};font-weight:600">${i.state}</span></td>
      <td>${escapeHtml(i.detail)}</td>
    </tr>`).join('');
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>oidc-bridge status</title>
<style>
  body { font-family: -apple-system, sans-serif; max-width: 720px; margin: 2em auto; }
  h1 { color: ${COLOR[opts.status]}; }
  table { border-collapse: collapse; width: 100%; }
  th, td { padding: 0.4em 0.8em; border-bottom: 1px solid #ddd; text-align: left; }
</style></head>
<body>
  <h1>oidc-bridge: ${opts.status}</h1>
  <p>version <code>${escapeHtml(opts.version)}</code> · build <code>${escapeHtml(opts.buildSha)}</code></p>
  <table>
    <thead><tr><th>probe</th><th>state</th><th>detail</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p style="color:#666;font-size:0.9em">Last refreshed at ${new Date().toISOString()}.</p>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

export function mountStatusRoute(opts: StatusRouteOpts) {
  const app = new Hono();
  app.get('/status', async (c) => {
    const items = await opts.probes();
    const status = worstOf(items);
    const wantsJson = c.req.query('format') === 'json' || (c.req.header('accept') ?? '').includes('application/json');
    if (wantsJson) {
      return c.json({ status, version: opts.version, build_sha: opts.buildSha, items });
    }
    c.header('content-type', 'text/html; charset=utf-8');
    return c.body(renderHtml({ version: opts.version, buildSha: opts.buildSha, status, items }));
  });
  return app;
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/status/route.ts src/status/route.test.ts
git commit -m "feat(status): GET /status (HTML + JSON content-negotiated)"
```

---

## Task 8: Wire middleware + status route into `app.ts`

**Files:**
- Modify: `src/app.ts`
- Modify: `src/server.ts`
- Modify: `src/config.ts`

Middleware order matters:

1. `requestId()` first (logs need it).
2. `pinoHttp()` second (start the timer immediately after).
3. `rateLimit()` third (429s should still get a request id and a log line).
4. Route handlers.

`/status` mounts at the same level as `/healthz`. `/healthz` is **excluded** from rate limiting (load balancers hit it constantly).

- [ ] **Step 1: Failing test (integration smoke)**

```ts
// src/app.test.ts (extend or create)
import { describe, it, expect } from 'vitest';
import { buildAppForTests } from './app.js';

describe('app integration', () => {
  it('GET /status returns 200 with version + build_sha', async () => {
    const app = await buildAppForTests({
      version: '0.0.0-test',
      buildSha: 'testsha',
      enableRateLimit: false,
    });
    const r = await app.request('/status', { headers: { accept: 'application/json' } });
    expect(r.status).toBe(200);
    const j = await r.json();
    expect(j.version).toBe('0.0.0-test');
    expect(j.build_sha).toBe('testsha');
  });

  it('every response carries x-request-id', async () => {
    const app = await buildAppForTests({ version: 'v', buildSha: 's', enableRateLimit: false });
    const r = await app.request('/healthz');
    expect(r.headers.get('x-request-id')).toMatch(/^[0-9a-f-]+$/);
  });

  it('/healthz is not rate-limited', async () => {
    const app = await buildAppForTests({ version: 'v', buildSha: 's', enableRateLimit: true, ipPerMin: 1, appPerMin: 1 });
    for (let i = 0; i < 10; i++) {
      expect((await app.request('/healthz', { headers: { 'x-forwarded-for': '1.1.1.1' } })).status).toBe(200);
    }
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement** — wire middleware in order in `buildApp`, exclude `/healthz` from rate-limit:

```ts
// src/app.ts (excerpt)
import { requestId } from './middleware/request-id.js';
import { pinoHttp } from './middleware/pino-http.js';
import { rateLimit } from './middleware/rate-limit-route.js';
import { mountStatusRoute } from './status/route.js';
import { runStatusProbes } from './status/probes.js';

export interface BuildAppOpts {
  // ... existing fields from earlier phases
  version: string;
  buildSha: string;
  ipHashSalt: string;
  rateLimit: { enabled: boolean; ipPerMin: number; appPerMin: number };
  // dependencies for status probes:
  dbUrl: string;
  masterKeyProvider: 'env' | 'file' | 'gcpsm';
  masterKeyDir?: string;
  activeKid: string;
  signingKeyPems: Record<string, string>;
}

export async function buildApp(opts: BuildAppOpts) {
  const app = new Hono();

  app.use('*', requestId());
  app.use('*', pinoHttp({ logger: opts.logger, ipSalt: opts.ipHashSalt }));

  // /healthz must be reachable at extremely high QPS (load balancers).
  app.get('/healthz', /* existing handler from Phase 0 */);

  // Status: not behind rate-limit either (operators need to see status during incidents).
  app.route('/', mountStatusRoute({
    version: opts.version,
    buildSha: opts.buildSha,
    probes: () => runStatusProbes({
      dbUrl: opts.dbUrl,
      masterKeyProvider: opts.masterKeyProvider,
      masterKeyDir: opts.masterKeyDir,
      activeKid: opts.activeKid,
      signingKeys: opts.signingKeyPems,
    }),
  }));

  // Rate limit applies to everything else.
  app.use('*', rateLimit(opts.rateLimit));

  // ...existing routes (oidc, admin, etc.)
  return app;
}
```

In `src/config.ts`, add:

```ts
export interface ObservabilityConfig {
  rateLimit: { enabled: boolean; ipPerMin: number; appPerMin: number };
  ipHashSalt: string;
  buildSha: string;
  version: string;
}

export function loadObservabilityConfig(env: NodeJS.ProcessEnv = process.env): ObservabilityConfig {
  return {
    rateLimit: {
      enabled: env.RATE_LIMIT_ENABLED !== 'false', // default on
      ipPerMin: Number(env.RATE_LIMIT_IP_PER_MIN ?? 60),
      appPerMin: Number(env.RATE_LIMIT_APP_PER_MIN ?? 600),
    },
    ipHashSalt: env.IP_HASH_SALT ?? randomBytes(16).toString('hex'),
    buildSha: env.BRIDGE_BUILD_SHA ?? 'dev',
    version: env.BRIDGE_VERSION ?? '0.0.0-dev',
  };
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/app.ts src/server.ts src/config.ts
git commit -m "feat(app): wire request-id, pino-http, rate-limit middleware + status route"
```

---

## Task 9: Optional OpenTelemetry init (lazy import)

**Files:**
- Create: `src/observability/otel.ts`
- Test: `src/observability/otel.test.ts`
- Modify: `src/server.ts`
- Modify: `package.json` — `optionalDependencies`

The point of this task is to **prove the lazy-load contract**: the OTel package is **never** imported when `OTEL_ENABLED !== '1'`. Self-host installs that don't want OTel just don't `pnpm install --include=optional`.

- [ ] **Step 1: Failing test**

```ts
// src/observability/otel.test.ts
import { describe, it, expect, vi } from 'vitest';
import { maybeStartOtel } from './otel.js';

describe('maybeStartOtel', () => {
  it('returns disabled status without importing OTel when env off', async () => {
    delete process.env.OTEL_ENABLED;
    const r = await maybeStartOtel();
    expect(r).toEqual({ kind: 'disabled' });
  });

  it('attempts dynamic import when env is on (acceptable to fail in tests)', async () => {
    process.env.OTEL_ENABLED = '1';
    const r = await maybeStartOtel();
    // In a test environment without the optional deps installed, expect kind=missing.
    expect(['started', 'missing']).toContain(r.kind);
    delete process.env.OTEL_ENABLED;
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/observability/otel.ts
export type OtelStartResult =
  | { kind: 'disabled' }
  | { kind: 'missing'; reason: string }
  | { kind: 'started' };

export async function maybeStartOtel(): Promise<OtelStartResult> {
  if (process.env.OTEL_ENABLED !== '1') {
    return { kind: 'disabled' };
  }
  try {
    // Both imports are dynamic so unused-on-self-host installs don't pay any startup cost.
    const { NodeSDK } = await import('@opentelemetry/sdk-node');
    const { getNodeAutoInstrumentations } = await import('@opentelemetry/auto-instrumentations-node');
    const sdk = new NodeSDK({
      instrumentations: [getNodeAutoInstrumentations()],
    });
    await sdk.start();
    // Best-effort shutdown on SIGTERM / SIGINT.
    for (const sig of ['SIGTERM', 'SIGINT'] as const) {
      process.once(sig, () => { sdk.shutdown().catch(() => {}); });
    }
    return { kind: 'started' };
  } catch (err) {
    return { kind: 'missing', reason: (err as Error).message };
  }
}
```

In `src/server.ts`, before `buildApp`:

```ts
const otelStatus = await maybeStartOtel();
if (otelStatus.kind === 'missing') {
  logger.warn({ reason: otelStatus.reason }, 'OTEL_ENABLED=1 but @opentelemetry packages not installed');
}
```

In `package.json`:

```json
{
  "optionalDependencies": {
    "@opentelemetry/sdk-node": "^0.x",
    "@opentelemetry/auto-instrumentations-node": "^0.x"
  }
}
```

(Pin to whatever the latest patch line is at implementation time; do not commit a version that doesn't exist on npm.)

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/observability/otel.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/observability/otel.ts src/observability/otel.test.ts src/server.ts package.json
git commit -m "feat(observability): optional OpenTelemetry SDK (lazy import, OTEL_ENABLED=1)"
```

---

## Task 10: RUNBOOK section

**Files:**
- Modify: `docs/RUNBOOK.md`

- [ ] **Step 1: Append**

```markdown
## Status page (`/status`)

- Public, no auth. Returns HTML by default; JSON when `Accept: application/json`
  or `?format=json`.
- Worst-of probes: green / yellow / red.
- Probes: db connectivity, master key fetch, JWKS sign+verify roundtrip,
  last-`/healthz` freshness.
- Operators of the public instance link the status page from the homepage.

## Rate limits

- Per-IP: `RATE_LIMIT_IP_PER_MIN` (default `60`).
- Per-app: `RATE_LIMIT_APP_PER_MIN` (default `600`).
- Sliding-window, in-memory, per-instance (multi-replica deployments do
  not share counters — acceptable for the initial release).
- Toggle entirely with `RATE_LIMIT_ENABLED=false` (e.g. self-host on a
  trusted network).
- Self-hosters behind a single shared NAT will see false-positive
  IP-rate-limit hits; raise `RATE_LIMIT_IP_PER_MIN` or disable.
- `/healthz` is exempt.

## Structured logs

- One JSON line per request: `{ time, level, request_id, method, path, status, latency_ms, user_agent, ip_hash }`.
- IPs are sha256-hashed with `IP_HASH_SALT` (random per process unless set explicitly).
- The pino redact list (set up in earlier phases) covers all known
  secret-shaped fields.
- Logs go to stdout. In `docker compose` deployments, `docker compose
  logs -f bridge` shows them. In Cloud Run, Cloud Logging picks them up.

## OpenTelemetry (opt-in)

- Set `OTEL_ENABLED=1` and configure standard OTel envs
  (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, etc.).
- `pnpm install --include=optional` to pull `@opentelemetry/sdk-node` +
  `auto-instrumentations-node`. Without that, the bridge logs a warning
  at boot and continues without tracing.
- The bridge does no OTel-specific code beyond `sdk.start()`; auto-
  instrumentations cover Hono, undici (Toss adapter), and pg.
```

- [ ] **Step 2: Commit**

```bash
git add docs/RUNBOOK.md
git commit -m "docs(runbook): status, rate limits, structured logs, OTel"
```

---

## Task 11: Final verification + open PR

**Files:** none.

- [ ] **Step 1: Full local check**

```bash
pnpm typecheck
pnpm lint
pnpm test
```

All green.

- [ ] **Step 2: Curl the running bridge**

```bash
pnpm dev &
PID=$!
sleep 1
curl -s http://localhost:8080/healthz
curl -s -H 'accept: application/json' http://localhost:8080/status | jq
curl -s -I http://localhost:8080/healthz | grep -i x-request-id
kill $PID
```

Expected: `/healthz` returns `{status:"ok"}`, `/status` returns a JSON
object with `status: "yellow"` (toss probe is intentionally absent at
runtime; the four runtime probes should be at least yellow on a
fresh-bootstrapped install), and every response has `X-Request-Id`.

- [ ] **Step 3: Push + open PR**

```bash
git push -u origin feat/zero-code-phase-08
gh pr create \
  --base main \
  --title "feat: zero-code Phase 8 — status, rate-limit, observability" \
  --body "$(cat <<'EOF'
## Summary
- `GET /status` (HTML + JSON) reuses Phase 7's probe shape (db, master-key, jwks, last-healthz). No auth.
- Per-IP + per-app sliding-window rate limit (in-memory). `RATE_LIMIT_ENABLED=false` to disable.
- One pino JSON log line per request, with x-request-id correlation. IPs are sha256-hashed.
- Optional OpenTelemetry SDK behind `OTEL_ENABLED=1`; lazy-imported via `optionalDependencies` so self-host installs that don't want it pay zero startup cost.

## Test plan
- [ ] `pnpm test` green; new middleware suites pass.
- [ ] /healthz exempt from rate-limit (10x in a row succeeds).
- [ ] /status JSON shape stable; HTML shape rendered.
- [ ] OTel disabled path imports nothing from `@opentelemetry/*`.
EOF
)"
```

- [ ] **Step 4: Wait for CI green and merge.**

---

## Done condition

- `GET /status` returns a worst-of report covering db, master-key, jwks, last-healthz.
- Every response carries `X-Request-Id` (echoed when caller supplied one and safe; freshly generated otherwise).
- Every request emits exactly one structured log line with `request_id`, `latency_ms`, `ip_hash`, no body.
- Per-IP and per-app rate limits in effect with sane defaults; `/healthz` exempt; toggle via env.
- `OTEL_ENABLED=1` opts in to tracing if optional deps are installed; `OTEL_ENABLED` unset is a zero-cost no-op.
- The pino redact list and the new middleware do not touch anything in `src/oidc/`, `src/toss/`, or `src/admin/`. The OIDC code path is unchanged from Phase 7.

That state is the foundation Phase 9 (self-host artifacts) builds on — Phase 9 packages this into a Docker image and a `docker-compose.yml` that runs Caddy, Postgres, and the bridge together; the bridge process itself is feature-complete by the end of Phase 8.
