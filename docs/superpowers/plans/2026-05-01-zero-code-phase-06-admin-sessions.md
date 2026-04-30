# oidc-bridge zero-code mode — Phase 6: admin sessions placeholder

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the `user_sessions` table (already present in Phase 1's schema) plus a stub session-login endpoint behind a feature flag so the future multi-user web console does not require a schema migration. Initial release continues to expose only API_TOKEN auth — this phase is forward-compatibility scaffolding, not a user-visible feature.

**Architecture:** Single new `sessions/` module owning a thin CRUD store (`createSession`, `getSession`, `revokeSession`, `purgeExpired`) over the existing pg/sqlite abstraction from Phase 1. One stub route `POST /admin/login` (and matching `POST /admin/logout`) gated by `BRIDGE_ENABLE_SESSION_LOGIN=1` env flag — flag-off (default) returns 404. Authentication uses bcrypt-hashed passwords on the existing `users` row (column added this phase: `users.password_hash`, nullable for users that only use API_TOKEN). Cookie is `__Host-bridge_session=<sid>; HttpOnly; Secure; SameSite=Lax; Path=/`. **No** session-bearing route is added to admin handlers — admin REST stays API_TOKEN-only — so a misconfigured flag cannot leak privileges.

**Tech stack:** TypeScript ESM strict, `bcryptjs` (already from Phase 2 for `client_secret`), `node:crypto.randomBytes` (session ids), `vitest`. No new prod deps.

---

## Universal invariants (apply to every task)

1. **TDD.** Failing test → minimal code → green → commit.
2. **Frequent commits.** Each red→green cycle is a commit. Conventional Commits.
3. **No premature abstractions.** No CSRF token rotation, no concurrent-session limit, no session "remember me" — those land in the actual web-console phase. Here we ship a single `(sid, user_id, expires_at)` row.
4. **No PII / secrets in logs.** This phase adds `password`, `password_hash`, and `set-cookie` (in res.headers) to the pino redact list.
5. **Bridge never spontaneously calls Toss.** Sessions are 100% local; Toss is not involved. The flag-off path is identical to "endpoint does not exist."
6. **Toss `refresh_token` never leaves the sealed wrapper.** Unaffected.
7. **Public clients use `Origin`, never `client_secret`.** Unaffected. Sessions are only for the admin/console surface.
8. **mTLS material never returns from any GET.** Unaffected.
9. **Cloud-agnostic.** No GCP-specific code.
10. **Self-host first-class.** Self-host operators that want a console preview set `BRIDGE_ENABLE_SESSION_LOGIN=1` and create a password via the CLI (Task 9). Default-off keeps the surface minimal.
11. **Bite-sized tasks.** Each step ≈2–5 minutes.
12. **Lint + typecheck + test pass on every commit.**

## Files this phase touches

```
src/
  storage/
    pg/migrations/0006_users_password_hash.sql       # NEW — ALTER TABLE users ADD COLUMN password_hash text NULL
    pg/migrations/0007_user_sessions_index.sql       # NEW — CREATE INDEX user_sessions_user_id_idx ON user_sessions (user_id)
    sqlite/migrations/0006_users_password_hash.sql   # NEW — same shape, sqlite
    sqlite/migrations/0007_user_sessions_index.sql   # NEW
    types.ts                                         # MODIFY — extend UserRow with password_hash; add UserSessionRow
  sessions/
    types.ts                                         # NEW — Session, SessionId, SessionStore interface
    store.ts                                         # NEW — pg + sqlite implementations behind one function (uses Storage)
    store.test.ts                                    # NEW — CRUD + expiry conformance
    service.ts                                       # NEW — login(email, password), logout(sid), validate(sid)
    service.test.ts                                  # NEW — bcrypt + happy + bad password + expired
    cookies.ts                                       # NEW — set-cookie + clear-cookie helpers
    cookies.test.ts                                  # NEW — header shape + flags
  admin/
    session-route.ts                                 # NEW — POST /admin/login + POST /admin/logout (flag-gated)
    session-route.test.ts                            # NEW — flag off=404, flag on=happy + bad creds
  config.ts                                          # MODIFY — read BRIDGE_ENABLE_SESSION_LOGIN
  app.ts                                             # MODIFY — mount session-route only when flag on
  logger.ts                                          # MODIFY — extend redact list
cli/
  commands/user-set-password.ts                      # NEW — set/reset a user's password locally
  index.ts                                           # MODIFY — register the command
docs/
  RUNBOOK.md                                         # MODIFY — section "session login (preview, opt-in)"
```

## Pre-flight (do this once before Task 1)

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-06 origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

If any check fails, stop and fix before continuing.

This phase depends on:

- Phase 1's `Storage` abstraction (pg + sqlite), `users` and `user_sessions` tables.
- Phase 2's `bcryptjs` use for `client_secret_hashes` (we re-use the same `BCRYPT_ROUNDS` constant) and the `Service` shape for service.users.\* / service.userSessions.\*.

---

## Task 1: Add `users.password_hash` migration (pg + sqlite)

**Files:**
- Create: `src/storage/pg/migrations/0006_users_password_hash.sql`
- Create: `src/storage/sqlite/migrations/0006_users_password_hash.sql`
- Modify: `src/storage/types.ts`
- Test: `src/storage/migrations.test.ts` (extend existing)

- [ ] **Step 1: Failing test (pg + sqlite)**

```ts
// src/storage/migrations.test.ts (extend the loop)
it('users.password_hash column exists after 0006', async () => {
  const storage = await openTestStorage(); // existing helper from Phase 1
  await storage.migrate();
  const cols = await storage.listColumns('users');
  expect(cols).toContain('password_hash');
});
```

- [ ] **Step 2: Run, expect failure**

```bash
pnpm vitest run src/storage/migrations.test.ts -t password_hash
```

Expected: column not found.

- [ ] **Step 3: Implement migrations**

`src/storage/pg/migrations/0006_users_password_hash.sql`:

```sql
ALTER TABLE users
  ADD COLUMN password_hash text;
```

`src/storage/sqlite/migrations/0006_users_password_hash.sql`:

```sql
ALTER TABLE users ADD COLUMN password_hash TEXT;
```

Update `UserRow` in `src/storage/types.ts`:

```ts
export interface UserRow {
  id: string;
  email: string;
  password_hash: string | null;
  created_at: string;
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/storage/pg/migrations/0006_users_password_hash.sql src/storage/sqlite/migrations/0006_users_password_hash.sql src/storage/types.ts src/storage/migrations.test.ts
git commit -m "feat(storage): users.password_hash nullable column (0006)"
```

---

## Task 2: Add `user_sessions` index migration

**Files:**
- Create: `src/storage/pg/migrations/0007_user_sessions_index.sql`
- Create: `src/storage/sqlite/migrations/0007_user_sessions_index.sql`

The `user_sessions` table itself was created in Phase 1. We add an index so `purgeExpired` and `revokeForUser` are not full-scans.

- [ ] **Step 1: Failing test**

```ts
// src/storage/migrations.test.ts (extend)
it('user_sessions has user_id index after 0007', async () => {
  const storage = await openTestStorage();
  await storage.migrate();
  const indexes = await storage.listIndexes('user_sessions');
  expect(indexes).toContain('user_sessions_user_id_idx');
});
```

`listIndexes` is the test helper added alongside `listColumns` in Phase 1's storage tests; if its name differs, adjust.

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement**

`src/storage/pg/migrations/0007_user_sessions_index.sql`:

```sql
CREATE INDEX user_sessions_user_id_idx ON user_sessions (user_id);
```

`src/storage/sqlite/migrations/0007_user_sessions_index.sql`:

```sql
CREATE INDEX user_sessions_user_id_idx ON user_sessions (user_id);
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/storage/pg/migrations/0007_user_sessions_index.sql src/storage/sqlite/migrations/0007_user_sessions_index.sql src/storage/migrations.test.ts
git commit -m "feat(storage): index user_sessions(user_id) (0007)"
```

---

## Task 3: `Session` types

**Files:**
- Create: `src/sessions/types.ts`

- [ ] **Step 1: Define types (no test — pure types)**

```ts
// src/sessions/types.ts
export type SessionId = string; // 32 hex chars (16 bytes random)

export interface Session {
  sid: SessionId;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  // No "remember me", no rolling expiry, no IP binding — out of scope for the placeholder.
}

export interface SessionStore {
  create(userId: string, ttlMs: number): Promise<Session>;
  get(sid: SessionId): Promise<Session | null>;
  revoke(sid: SessionId): Promise<void>;
  revokeForUser(userId: string): Promise<void>;
  purgeExpired(now: Date): Promise<number>; // returns count purged
}
```

- [ ] **Step 2: Commit**

```bash
git add src/sessions/types.ts
git commit -m "feat(sessions): Session + SessionStore interfaces"
```

---

## Task 4: `SessionStore` implementation against `Storage`

**Files:**
- Create: `src/sessions/store.ts`
- Test: `src/sessions/store.test.ts`

Both pg and sqlite implementations live behind a single function that takes the `Storage` from Phase 1 — we don't duplicate the implementation; it's a thin wrapper around `storage.exec` / `storage.query`.

- [ ] **Step 1: Failing test (run against both pg + sqlite via the conformance harness from Phase 1)**

```ts
// src/sessions/store.test.ts
import { describe, it, expect } from 'vitest';
import { runStorageMatrix } from '../storage/test-matrix.js'; // from Phase 1
import { createSessionStore } from './store.js';

runStorageMatrix('SessionStore', (openStorage) => {
  it('create then get returns the row', async () => {
    const storage = await openStorage();
    await storage.migrate();
    await storage.exec(`INSERT INTO users (id, email) VALUES ('u_1', 'a@b')`);
    const store = createSessionStore(storage);
    const created = await store.create('u_1', 60_000);
    expect(created.sid).toMatch(/^[0-9a-f]{32}$/);
    const fetched = await store.get(created.sid);
    expect(fetched?.userId).toBe('u_1');
  });

  it('get returns null for unknown sid', async () => {
    const storage = await openStorage();
    await storage.migrate();
    const store = createSessionStore(storage);
    expect(await store.get('deadbeefdeadbeefdeadbeefdeadbeef')).toBeNull();
  });

  it('revoke removes the row', async () => {
    const storage = await openStorage();
    await storage.migrate();
    await storage.exec(`INSERT INTO users (id, email) VALUES ('u_1', 'a@b')`);
    const store = createSessionStore(storage);
    const s = await store.create('u_1', 60_000);
    await store.revoke(s.sid);
    expect(await store.get(s.sid)).toBeNull();
  });

  it('revokeForUser removes all sessions for user', async () => {
    const storage = await openStorage();
    await storage.migrate();
    await storage.exec(`INSERT INTO users (id, email) VALUES ('u_1', 'a@b')`);
    const store = createSessionStore(storage);
    const a = await store.create('u_1', 60_000);
    const b = await store.create('u_1', 60_000);
    await store.revokeForUser('u_1');
    expect(await store.get(a.sid)).toBeNull();
    expect(await store.get(b.sid)).toBeNull();
  });

  it('purgeExpired removes only expired rows', async () => {
    const storage = await openStorage();
    await storage.migrate();
    await storage.exec(`INSERT INTO users (id, email) VALUES ('u_1', 'a@b')`);
    const store = createSessionStore(storage);
    const fresh = await store.create('u_1', 60_000);
    // Insert an already-expired row directly.
    await storage.exec(
      `INSERT INTO user_sessions (sid, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
      ['ffffffffffffffffffffffffffffffff', 'u_1', new Date().toISOString(), new Date(Date.now() - 1000).toISOString()],
    );
    const purged = await store.purgeExpired(new Date());
    expect(purged).toBe(1);
    expect(await store.get(fresh.sid)).not.toBeNull();
    expect(await store.get('ffffffffffffffffffffffffffffffff')).toBeNull();
  });
});
```

- [ ] **Step 2: Run, expect failures**

```bash
pnpm vitest run src/sessions/store.test.ts
```

- [ ] **Step 3: Implement**

```ts
// src/sessions/store.ts
import { randomBytes } from 'node:crypto';
import type { Storage } from '../storage/types.js';
import type { Session, SessionId, SessionStore } from './types.js';

export function createSessionStore(storage: Storage): SessionStore {
  return {
    async create(userId, ttlMs) {
      const sid = randomBytes(16).toString('hex');
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlMs);
      await storage.exec(
        `INSERT INTO user_sessions (sid, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)`,
        [sid, userId, now.toISOString(), expiresAt.toISOString()],
      );
      return { sid, userId, createdAt: now, expiresAt };
    },

    async get(sid) {
      const rows = await storage.query<{
        sid: string; user_id: string; created_at: string; expires_at: string;
      }>(`SELECT sid, user_id, created_at, expires_at FROM user_sessions WHERE sid = $1`, [sid]);
      if (rows.length === 0) return null;
      const r = rows[0]!;
      const expiresAt = new Date(r.expires_at);
      if (expiresAt.getTime() <= Date.now()) {
        // Treat expired as gone, even if not yet purged.
        return null;
      }
      return { sid: r.sid, userId: r.user_id, createdAt: new Date(r.created_at), expiresAt };
    },

    async revoke(sid) {
      await storage.exec(`DELETE FROM user_sessions WHERE sid = $1`, [sid]);
    },

    async revokeForUser(userId) {
      await storage.exec(`DELETE FROM user_sessions WHERE user_id = $1`, [userId]);
    },

    async purgeExpired(now) {
      const r = await storage.exec<{ rowsAffected: number }>(
        `DELETE FROM user_sessions WHERE expires_at <= $1`,
        [now.toISOString()],
      );
      return r?.rowsAffected ?? 0;
    },
  };
}
```

If your `storage.exec` returns a different shape than `{ rowsAffected }`, adapt — the existing pg + sqlite wrappers from Phase 1 already expose this. If they don't, change `purgeExpired` to do a `SELECT count(*)` first then `DELETE`; do not touch `Storage`.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/sessions/store.ts src/sessions/store.test.ts
git commit -m "feat(sessions): pg+sqlite SessionStore (create/get/revoke/purge)"
```

---

## Task 5: `sessionService` — login / logout / validate (bcrypt)

**Files:**
- Create: `src/sessions/service.ts`
- Test: `src/sessions/service.test.ts`

The service ties `bcryptjs` password verification to `SessionStore.create`. It's the only place that reads `users.password_hash`.

- [ ] **Step 1: Failing test**

```ts
// src/sessions/service.test.ts
import { describe, it, expect } from 'vitest';
import bcrypt from 'bcryptjs';
import { createSessionService } from './service.js';
import type { SessionStore } from './types.js';

function fakeStore(): SessionStore & { rows: Map<string, { sid: string; userId: string; createdAt: Date; expiresAt: Date }> } {
  const rows = new Map<string, { sid: string; userId: string; createdAt: Date; expiresAt: Date }>();
  return {
    rows,
    async create(userId, ttlMs) {
      const sid = `sid_${rows.size + 1}`;
      const r = { sid, userId, createdAt: new Date(), expiresAt: new Date(Date.now() + ttlMs) };
      rows.set(sid, r);
      return r;
    },
    async get(sid) { return rows.get(sid) ?? null; },
    async revoke(sid) { rows.delete(sid); },
    async revokeForUser(userId) { for (const [k, v] of rows) if (v.userId === userId) rows.delete(k); },
    async purgeExpired() { return 0; },
  };
}

describe('createSessionService', () => {
  it('login returns a session for correct password', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async (email) => email === 'a@b' ? { id: 'u_1', passwordHash: hash } : null,
    });
    const s = await svc.login('a@b', 'secret123');
    expect(s.kind).toBe('ok');
    if (s.kind === 'ok') expect(s.session.userId).toBe('u_1');
  });

  it('login returns invalid_credentials for wrong password', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: hash }),
    });
    const s = await svc.login('a@b', 'wrong');
    expect(s.kind).toBe('invalid_credentials');
  });

  it('login returns invalid_credentials for unknown email (no enumeration)', async () => {
    const store = fakeStore();
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => null,
    });
    const s = await svc.login('nobody@b', 'whatever');
    expect(s.kind).toBe('invalid_credentials');
  });

  it('login returns no_password_set when user has no hash', async () => {
    const store = fakeStore();
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: null }),
    });
    const s = await svc.login('a@b', 'whatever');
    expect(s.kind).toBe('no_password_set');
  });

  it('logout deletes the session', async () => {
    const store = fakeStore();
    const hash = bcrypt.hashSync('secret123', 4);
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => ({ id: 'u_1', passwordHash: hash }),
    });
    const s = await svc.login('a@b', 'secret123');
    if (s.kind !== 'ok') throw new Error('expected login ok');
    await svc.logout(s.session.sid);
    expect(await store.get(s.session.sid)).toBeNull();
  });

  it('validate returns null for unknown sid', async () => {
    const store = fakeStore();
    const svc = createSessionService({
      store,
      ttlMs: 60_000,
      lookupUser: async () => null,
    });
    expect(await svc.validate('does-not-exist')).toBeNull();
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/sessions/service.ts
import bcrypt from 'bcryptjs';
import type { Session, SessionStore } from './types.js';

export type LoginResult =
  | { kind: 'ok'; session: Session }
  | { kind: 'invalid_credentials' }
  | { kind: 'no_password_set' };

export interface SessionServiceDeps {
  store: SessionStore;
  ttlMs: number;
  lookupUser: (email: string) => Promise<{ id: string; passwordHash: string | null } | null>;
}

export interface SessionService {
  login(email: string, password: string): Promise<LoginResult>;
  logout(sid: string): Promise<void>;
  validate(sid: string): Promise<Session | null>;
}

export function createSessionService(deps: SessionServiceDeps): SessionService {
  return {
    async login(email, password) {
      const u = await deps.lookupUser(email);
      // Always run bcrypt to keep timing constant for unknown vs. known users.
      const hash = u?.passwordHash ?? '$2a$04$0000000000000000000000.0000000000000000000000000000000000';
      const ok = await bcrypt.compare(password, hash);
      if (!u) return { kind: 'invalid_credentials' };
      if (u.passwordHash === null) return { kind: 'no_password_set' };
      if (!ok) return { kind: 'invalid_credentials' };
      const session = await deps.store.create(u.id, deps.ttlMs);
      return { kind: 'ok', session };
    },

    async logout(sid) {
      await deps.store.revoke(sid);
    },

    async validate(sid) {
      return deps.store.get(sid);
    },
  };
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/sessions/service.ts src/sessions/service.test.ts
git commit -m "feat(sessions): login/logout/validate service with bcrypt + constant-timing"
```

---

## Task 6: Session cookie helpers

**Files:**
- Create: `src/sessions/cookies.ts`
- Test: `src/sessions/cookies.test.ts`

The cookie name is `__Host-bridge_session` (the `__Host-` prefix forces `Secure`, `Path=/`, and no `Domain`, which closes a subdomain-takeover vector — see RFC 6265bis).

- [ ] **Step 1: Failing test**

```ts
// src/sessions/cookies.test.ts
import { describe, it, expect } from 'vitest';
import { setSessionCookie, clearSessionCookie } from './cookies.js';

describe('setSessionCookie', () => {
  it('produces __Host- cookie with HttpOnly Secure SameSite=Lax Path=/', () => {
    const v = setSessionCookie('abc123', new Date('2030-01-01T00:00:00Z'));
    expect(v).toContain('__Host-bridge_session=abc123');
    expect(v).toContain('Path=/');
    expect(v).toContain('HttpOnly');
    expect(v).toContain('Secure');
    expect(v).toContain('SameSite=Lax');
    expect(v).toContain('Expires=Tue, 01 Jan 2030 00:00:00 GMT');
    expect(v).not.toContain('Domain=');
  });
});

describe('clearSessionCookie', () => {
  it('produces a Max-Age=0 same-shape cookie', () => {
    const v = clearSessionCookie();
    expect(v).toContain('__Host-bridge_session=');
    expect(v).toContain('Max-Age=0');
    expect(v).toContain('HttpOnly');
    expect(v).toContain('Secure');
    expect(v).toContain('SameSite=Lax');
    expect(v).toContain('Path=/');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/sessions/cookies.ts
const NAME = '__Host-bridge_session';

export function setSessionCookie(sid: string, expiresAt: Date): string {
  return `${NAME}=${sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiresAt.toUTCString()}`;
}

export function clearSessionCookie(): string {
  return `${NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

export function readSessionCookie(headerValue: string | null | undefined): string | null {
  if (!headerValue) return null;
  for (const piece of headerValue.split(';')) {
    const [k, ...rest] = piece.trim().split('=');
    if (k === NAME) return rest.join('=') || null;
  }
  return null;
}
```

`readSessionCookie` is exported for completeness (the future console will use it); covered indirectly by Task 7 route tests.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/sessions/cookies.ts src/sessions/cookies.test.ts
git commit -m "feat(sessions): __Host- cookie helpers"
```

---

## Task 7: Stub `POST /admin/login` + `POST /admin/logout` (flag-gated)

**Files:**
- Create: `src/admin/session-route.ts`
- Test: `src/admin/session-route.test.ts`
- Modify: `src/config.ts` (read `BRIDGE_ENABLE_SESSION_LOGIN`)
- Modify: `src/app.ts` (mount conditionally)

`POST /admin/login` body: `{ email, password }`. Response on success: `200 { ok: true }` + `Set-Cookie`. On failure: `401 { error: "invalid_credentials" | "no_password_set" }`. Always returns the SAME body for unknown-user vs wrong-password (`invalid_credentials`) — no enumeration.

`POST /admin/logout` reads the cookie, revokes the session, returns `200 { ok: true }` + clear-cookie. Idempotent.

When the flag is off, both routes are not registered at all → Hono returns 404 (consistent with "endpoint does not exist"). We test this explicitly so a flip-back-to-default cannot accidentally leave the routes mounted.

- [ ] **Step 1: Failing test**

```ts
// src/admin/session-route.test.ts
import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import bcrypt from 'bcryptjs';
import { mountSessionRoute } from './session-route.js';

function buildTestApp(opts: { enabled: boolean; passwordHash: string | null }) {
  const sessions = new Map<string, { sid: string; userId: string; createdAt: Date; expiresAt: Date }>();
  const service = {
    async login(email: string, password: string) {
      if (email !== 'a@b') return { kind: 'invalid_credentials' as const };
      if (opts.passwordHash === null) return { kind: 'no_password_set' as const };
      const ok = await bcrypt.compare(password, opts.passwordHash);
      if (!ok) return { kind: 'invalid_credentials' as const };
      const sid = 'sid_test';
      const session = { sid, userId: 'u_1', createdAt: new Date(), expiresAt: new Date(Date.now() + 60_000) };
      sessions.set(sid, session);
      return { kind: 'ok' as const, session };
    },
    async logout(sid: string) { sessions.delete(sid); },
    async validate(sid: string) { return sessions.get(sid) ?? null; },
  };
  const app = new Hono();
  if (opts.enabled) {
    app.route('/', mountSessionRoute({ service }));
  }
  return app;
}

describe('session-route', () => {
  it('flag off: POST /admin/login returns 404', async () => {
    const app = buildTestApp({ enabled: false, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 's' }),
    });
    expect(r.status).toBe(404);
  });

  it('flag on, valid credentials: 200 + Set-Cookie', async () => {
    const app = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 's' }),
    });
    expect(r.status).toBe(200);
    const cookie = r.headers.get('set-cookie');
    expect(cookie).toContain('__Host-bridge_session=sid_test');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
  });

  it('flag on, wrong password: 401 invalid_credentials, no Set-Cookie', async () => {
    const app = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 'wrong' }),
    });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'invalid_credentials' });
    expect(r.headers.get('set-cookie')).toBeNull();
  });

  it('flag on, unknown user: 401 invalid_credentials (no enumeration)', async () => {
    const app = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@b', password: 'whatever' }),
    });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'invalid_credentials' });
  });

  it('flag on, user with no password_hash: 401 no_password_set', async () => {
    const app = buildTestApp({ enabled: true, passwordHash: null });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 'anything' }),
    });
    expect(r.status).toBe(401);
    expect(await r.json()).toEqual({ error: 'no_password_set' });
  });

  it('flag on, logout clears the cookie and revokes', async () => {
    const app = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const login = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'a@b', password: 's' }),
    });
    expect(login.status).toBe(200);
    const sentCookie = login.headers.get('set-cookie') ?? '';
    const r = await app.request('/admin/logout', {
      method: 'POST',
      headers: { cookie: sentCookie.split(';')[0]! }, // just __Host-bridge_session=sid_test
    });
    expect(r.status).toBe(200);
    expect(r.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  it('flag on, missing body fields: 400 invalid_request', async () => {
    const app = buildTestApp({ enabled: true, passwordHash: bcrypt.hashSync('s', 4) });
    const r = await app.request('/admin/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ error: 'invalid_request' });
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// src/admin/session-route.ts
import { Hono } from 'hono';
import { z } from 'zod';
import type { SessionService } from '../sessions/service.js';
import { setSessionCookie, clearSessionCookie, readSessionCookie } from '../sessions/cookies.js';

const LoginBody = z.object({ email: z.string().min(1), password: z.string().min(1) });

export function mountSessionRoute(opts: { service: SessionService }) {
  const app = new Hono();

  app.post('/admin/login', async (c) => {
    let body: unknown;
    try { body = await c.req.json(); }
    catch { return c.json({ error: 'invalid_request' }, 400); }
    const parsed = LoginBody.safeParse(body);
    if (!parsed.success) return c.json({ error: 'invalid_request' }, 400);
    const r = await opts.service.login(parsed.data.email, parsed.data.password);
    if (r.kind === 'invalid_credentials') return c.json({ error: 'invalid_credentials' }, 401);
    if (r.kind === 'no_password_set') return c.json({ error: 'no_password_set' }, 401);
    c.header('set-cookie', setSessionCookie(r.session.sid, r.session.expiresAt));
    return c.json({ ok: true });
  });

  app.post('/admin/logout', async (c) => {
    const sid = readSessionCookie(c.req.header('cookie'));
    if (sid) await opts.service.logout(sid);
    c.header('set-cookie', clearSessionCookie());
    return c.json({ ok: true });
  });

  return app;
}
```

In `src/app.ts`, add inside `buildApp`:

```ts
if (opts.config.enableSessionLogin) {
  app.route('/', mountSessionRoute({ service: opts.sessionService }));
}
```

In `src/config.ts`, extend the bridge config loader:

```ts
export interface BridgeConfig {
  // ...existing fields
  enableSessionLogin: boolean;
}

export function loadBridgeConfig(env: NodeJS.ProcessEnv = process.env): BridgeConfig {
  return {
    // ...existing
    enableSessionLogin: env.BRIDGE_ENABLE_SESSION_LOGIN === '1',
  };
}
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run src/admin/session-route.test.ts
```

- [ ] **Step 5: Commit**

```bash
git add src/admin/session-route.ts src/admin/session-route.test.ts src/config.ts src/app.ts
git commit -m "feat(admin): flag-gated POST /admin/login + /admin/logout (placeholder)"
```

---

## Task 8: Wire purgeExpired into a startup hook

**Files:**
- Modify: `src/server.ts`
- Test: `src/server.test.ts`

We don't run a cron — too much for the placeholder. We do call `purgeExpired` once at startup so old rows don't accumulate forever in long-lived self-hosts. Subsequent purges happen the next time the process restarts (acceptable for a placeholder).

- [ ] **Step 1: Failing test**

```ts
// src/server.test.ts (extend)
import { runStartupTasks } from './server.js';

describe('runStartupTasks', () => {
  it('calls sessionStore.purgeExpired once with current time', async () => {
    const calls: Date[] = [];
    const store = {
      create: async () => ({ sid: '', userId: '', createdAt: new Date(), expiresAt: new Date() }),
      get: async () => null,
      revoke: async () => {},
      revokeForUser: async () => {},
      purgeExpired: async (now: Date) => { calls.push(now); return 0; },
    };
    await runStartupTasks({ sessionStore: store });
    expect(calls.length).toBe(1);
    expect(calls[0]).toBeInstanceOf(Date);
  });
});
```

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement**

```ts
// src/server.ts (export this and call from main)
import type { SessionStore } from './sessions/types.js';

export async function runStartupTasks(deps: { sessionStore: SessionStore }): Promise<void> {
  await deps.sessionStore.purgeExpired(new Date());
}
```

Add to `main()`:

```ts
await runStartupTasks({ sessionStore: createSessionStore(storage) });
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add src/server.ts src/server.test.ts
git commit -m "feat(server): purge expired sessions on startup"
```

---

## Task 9: CLI `user set-password`

**Files:**
- Create: `cli/commands/user-set-password.ts`
- Modify: `cli/index.ts`
- Test: `cli/commands/user-set-password.test.ts`

The only way to get a password into the DB. Self-host operators who want to preview the future console run:

```bash
pnpm bridge user set-password --email a@b
# (prompts for password, hashes, writes to users.password_hash)
```

The CLI talks directly to local SQLite (bootstrap mode) or to the Admin REST `PATCH /admin/users/:id` endpoint (server mode) — but `PATCH /admin/users/:id` is **not added in this phase** (out of scope). For now the CLI is **bootstrap-mode only**: requires `BRIDGE_DB_URL` to be a `sqlite://` URL, opens it directly. Operators with Postgres set the column with `psql` (documented in RUNBOOK).

- [ ] **Step 1: Failing test**

```ts
// cli/commands/user-set-password.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import bcrypt from 'bcryptjs';
import { runUserSetPassword } from './user-set-password.js';
import { openSqliteStorage } from '../../src/storage/sqlite/storage.js';

describe('user set-password (bootstrap)', () => {
  let dir: string;
  let dbUrl: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'bridge-cli-'));
    dbUrl = `sqlite://${join(dir, 'bridge.db')}`;
  });

  it('hashes password and stores on users row', async () => {
    const storage = await openSqliteStorage(dbUrl);
    await storage.migrate();
    await storage.exec(`INSERT INTO users (id, email) VALUES ('u_1', 'a@b')`);
    await runUserSetPassword({ dbUrl, email: 'a@b', plaintextPassword: 'hunter2' });
    const rows = await storage.query<{ password_hash: string | null }>(
      `SELECT password_hash FROM users WHERE email = $1`, ['a@b'],
    );
    expect(rows[0]?.password_hash).not.toBeNull();
    expect(bcrypt.compareSync('hunter2', rows[0]!.password_hash!)).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });

  it('errors when user does not exist', async () => {
    await expect(
      runUserSetPassword({ dbUrl, email: 'nobody@b', plaintextPassword: 'x' }),
    ).rejects.toThrow(/no user with email/);
    rmSync(dir, { recursive: true, force: true });
  });

  it('rejects non-sqlite dbUrl (bootstrap mode only)', async () => {
    await expect(
      runUserSetPassword({ dbUrl: 'postgres://x', email: 'a@b', plaintextPassword: 'x' }),
    ).rejects.toThrow(/sqlite/);
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/user-set-password.ts
import bcrypt from 'bcryptjs';
import { openSqliteStorage } from '../../src/storage/sqlite/storage.js';

const BCRYPT_ROUNDS = 12;

export interface RunUserSetPasswordOpts {
  dbUrl: string;
  email: string;
  plaintextPassword: string;
}

export async function runUserSetPassword(opts: RunUserSetPasswordOpts): Promise<void> {
  if (!opts.dbUrl.startsWith('sqlite://')) {
    throw new Error('user set-password is bootstrap-mode only; dbUrl must start with sqlite://');
  }
  const storage = await openSqliteStorage(opts.dbUrl);
  await storage.migrate();
  const rows = await storage.query<{ id: string }>(
    `SELECT id FROM users WHERE email = $1`,
    [opts.email],
  );
  if (rows.length === 0) {
    throw new Error(`no user with email=${opts.email}`);
  }
  const hash = await bcrypt.hash(opts.plaintextPassword, BCRYPT_ROUNDS);
  await storage.exec(
    `UPDATE users SET password_hash = $1 WHERE id = $2`,
    [hash, rows[0]!.id],
  );
}
```

In `cli/index.ts`, register the command:

```ts
program
  .command('user set-password')
  .requiredOption('--email <email>')
  .action(async (cmd) => {
    const password = await promptHidden('Password: ');
    await runUserSetPassword({
      dbUrl: requireEnv('BRIDGE_DB_URL'),
      email: cmd.email,
      plaintextPassword: password,
    });
    console.log(`Password set for ${cmd.email}.`);
  });
```

`promptHidden` is the existing helper from Phase 2 / 7's CLI work. If it does not yet exist on this branch (it lands in Phase 7), you may stub it as `prompt-sync` or read from stdin without echoing — keep the import named `promptHidden` so Phase 7 wires the real implementation in one place.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/commands/user-set-password.ts cli/commands/user-set-password.test.ts cli/index.ts
git commit -m "feat(cli): user set-password (bootstrap mode, sqlite only)"
```

---

## Task 10: Extend pino redact list

**Files:**
- Modify: `src/logger.ts`
- Modify: `src/logger.test.ts`

- [ ] **Step 1: Failing test**

```ts
// src/logger.test.ts (extend)
it('redacts password and password_hash and set-cookie', () => {
  const out = captureLog((l) => l.info({
    password: 'PLAINTEXT',
    password_hash: '$2a$12$XXXXXXXX',
    res: { headers: { 'set-cookie': '__Host-bridge_session=SECRETSID; ...' } },
  }, 'leak-check'));
  expect(out).not.toContain('PLAINTEXT');
  expect(out).not.toContain('$2a$12$XXXXXXXX');
  expect(out).not.toContain('SECRETSID');
});
```

- [ ] **Step 2: Run, expect failure**

- [ ] **Step 3: Implement** — append to redact paths:

```ts
'password',
'password_hash',
'res.headers.set-cookie',
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git commit -am "chore(logger): redact password fields and set-cookie"
```

---

## Task 11: RUNBOOK section

**Files:**
- Modify: `docs/RUNBOOK.md`

- [ ] **Step 1: Append**

```markdown
## Session login (preview, opt-in)

The bridge ships a placeholder `POST /admin/login` + `POST /admin/logout`
behind `BRIDGE_ENABLE_SESSION_LOGIN=1`. Initial release does not use it
for anything — Admin REST stays API_TOKEN-only. The placeholder exists so
the future web console does not require a schema migration.

To preview:

1. Set a password for an existing user (sqlite bootstrap only):

   ```bash
   BRIDGE_DB_URL=sqlite:///var/lib/bridge/bridge.db \
     pnpm bridge user set-password --email you@example.com
   ```

   For Postgres, run SQL directly:

   ```sql
   UPDATE users SET password_hash = $1 WHERE email = 'you@example.com';
   -- $1 is the output of:  node -e "console.log(require('bcryptjs').hashSync(process.argv[1], 12))" 'yourpassword'
   ```

2. Restart the bridge with `BRIDGE_ENABLE_SESSION_LOGIN=1`.

3. `POST /admin/login` with `{ email, password }`. The response sets a
   `__Host-bridge_session` cookie (`HttpOnly`, `Secure`, `SameSite=Lax`).

4. There are no session-bearing routes yet. Validate with `POST /admin/logout`.

To turn it back off, simply restart without the env var. The routes
disappear (return 404). Any existing rows in `user_sessions` are kept and
expired naturally — they cause no harm because nothing reads them.

`Secure` flag on the cookie means the bridge must be reached via HTTPS
(behind Caddy / Cloud Run). Plain HTTP rejects the cookie.
```

- [ ] **Step 2: Commit**

```bash
git add docs/RUNBOOK.md
git commit -m "docs(runbook): session-login preview instructions"
```

---

## Task 12: Final verification + open PR

**Files:** none.

- [ ] **Step 1: Full local check**

```bash
pnpm typecheck
pnpm lint
pnpm test
```

All green.

- [ ] **Step 2: Confirm flag-off path is truly off**

```bash
BRIDGE_ENABLE_SESSION_LOGIN=0 \
BRIDGE_DB_URL=sqlite::memory: \
pnpm tsx -e "
  import('./src/server.js').then(async (m) => {
    const app = await m.buildAppForSelfTest();
    const r = await app.request('/admin/login', { method: 'POST' });
    console.log('status=' + r.status);
  });
"
```

Expected: `status=404`. (`buildAppForSelfTest` is the existing helper that exposes `buildApp(...)` for tests; if your bootstrap uses a different name, substitute.)

- [ ] **Step 3: Push + open PR**

```bash
git push -u origin feat/zero-code-phase-06
gh pr create \
  --base main \
  --title "feat: zero-code Phase 6 — admin sessions placeholder" \
  --body "$(cat <<'EOF'
## Summary
- Adds `users.password_hash` (nullable) + index on `user_sessions(user_id)`.
- Implements `SessionStore` (pg + sqlite) and `sessionService` (bcrypt + constant-time).
- Stubs `POST /admin/login` / `POST /admin/logout` behind `BRIDGE_ENABLE_SESSION_LOGIN=1`. Default off → routes return 404.
- Adds `pnpm bridge user set-password` (sqlite bootstrap-mode only).
- Cookie is `__Host-bridge_session` (`HttpOnly` `Secure` `SameSite=Lax`).
- Admin REST remains API_TOKEN-only — no privilege change in initial release.

## Test plan
- [ ] `pnpm test` green; storage matrix runs the new migrations on pg + sqlite.
- [ ] Flag off: POST /admin/login → 404.
- [ ] Flag on, valid creds: 200 + Set-Cookie.
- [ ] Flag on, wrong password vs unknown email: identical 401 invalid_credentials response.
- [ ] No new prod deps (uses existing bcryptjs).
EOF
)"
```

- [ ] **Step 4: Wait for CI green and merge.**

---

## Done condition

- `users.password_hash` and the new `user_sessions(user_id)` index exist on both backends.
- With `BRIDGE_ENABLE_SESSION_LOGIN` unset or `0`, the bridge behaves identically to Phase 5 (no new routes, no new attack surface).
- With the flag set, `POST /admin/login` and `POST /admin/logout` work as documented; no other admin route accepts the session cookie (admin REST stays API_TOKEN-only).
- `runStartupTasks` purges expired session rows once at boot.
- The CLI can set a password on a user row in a sqlite bootstrap DB.
- The pino redact list covers `password`, `password_hash`, and `set-cookie`.

That state is the foundation Phase 7 (CLI bootstrap + doctor) builds on — Phase 7 wires `bootstrap` and `doctor` end-to-end against a real (sandbox) Toss cert, using the migrations and CLI scaffold from Phases 1, 2, and 6.
