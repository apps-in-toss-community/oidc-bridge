# Phase 0 — Project skeleton

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wipe the legacy `/verify` surface, install structured logging, and lock the directory layout the rest of the phases will fill in. Net effect: a Hono app that serves `GET /healthz` and nothing else, with pino logs, all build/lint/typecheck/test pipelines green.

**Architecture:** Single Hono factory in `src/app.ts` mounting only `GET /healthz`. `src/server.ts` boots the app via `@hono/node-server` and wires pino. Empty placeholder directories under `src/` stake out modules for later phases (so import paths stabilize early). The legacy Toss `/verify` adapter is deleted outright — the spec mandates a clean break.

**Tech stack:** TypeScript ESM strict, Hono 4.x, `@hono/node-server`, **pino** (new), **pino-pretty** (dev only), tsdown, vitest, biome.

---

## Universal invariants (apply to every task)

See [`2026-05-01-zero-code-mode-index.md`](./2026-05-01-zero-code-mode-index.md#universal-invariants) for the full list. Phase 0 leans on these in particular:

- **TDD.** Write the failing test, run it red, write minimal code, run it green, commit.
- **No PII / secrets in logs.** Pino is configured with a redact list from day one.
- **Self-host first-class.** `pnpm build && pnpm start` and `docker compose up` both still produce a working `/healthz` at the end of every task.
- **Lint + typecheck + test pass on every commit.** The pre-commit hook runs biome on staged files; CI runs `pnpm lint && pnpm typecheck && pnpm build && pnpm test`.

## Files touched in this phase

**Created:**
- `src/logger.ts` — pino factory with redaction.
- `src/logger.test.ts` — verifies redact list.
- `src/oidc/.gitkeep`
- `src/toss/.gitkeep` (already exists, keep)
- `src/storage/.gitkeep`
- `src/master-keys/.gitkeep`
- `src/apps/.gitkeep`
- `src/audit/.gitkeep`
- `cli/.gitkeep`
- `MIGRATION.md` (root) — records the breaking change for self-host operators.

**Modified:**
- `src/app.ts` — strip `/verify`, keep only `/healthz`.
- `src/app.test.ts` — drop `/verify` tests, keep `/healthz` test, add 404-on-`/verify` regression test.
- `src/server.ts` — replace `console.log` with pino; log request lifecycle.
- `package.json` — add `pino`, `pino-pretty`; remove unused.
- `README.md` — replace M0 framing with zero-code-mode pointer.

**Deleted:**
- `src/toss/verify.ts`
- `src/toss/verify.test.ts`

## Pre-flight check

The branch `zero-code-mode` (already created from `origin/main`) is the integration branch for the entire spec. Phase 0 commits land directly on this branch. The PR for Phase 0 merges `zero-code-mode` → `main` only after **all 12 phases** are done, but each phase still ends on a clean tree so any phase can be backed out independently.

Before starting, confirm cwd and branch.

```bash
pwd
# expect: /…/oidc-bridge-jwt-signature-verification

git branch --show-current
# expect: zero-code-mode

git status
# expect: clean (or only previously-committed spec/index plan)
```

If the branch is wrong: `git checkout zero-code-mode`. Do not start Phase 0 from any other branch.

---

## Task 1: Delete the legacy `/verify` surface

The spec explicitly removes `/verify`. We delete the route, the adapter, and the tests in one commit so the regression is unambiguous.

**Files:**
- Modify: `src/app.ts`
- Modify: `src/app.test.ts`
- Delete: `src/toss/verify.ts`
- Delete: `src/toss/verify.test.ts`

- [ ] **Step 1: Write the regression test that `/verify` is gone**

Replace the entire body of `src/app.test.ts` with:

```ts
import { describe, expect, it } from 'vitest';
import { createApp } from './app.js';

describe('GET /healthz', () => {
  it('returns ok', async () => {
    const app = createApp();
    const res = await app.request('/healthz');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });
});

describe('legacy /verify is gone', () => {
  it('returns 404 for POST /verify', async () => {
    const app = createApp();
    const res = await app.request('/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ authorizationCode: 'x', referrer: 'SANDBOX' }),
    });
    expect(res.status).toBe(404);
  });
});
```

- [ ] **Step 2: Run tests and confirm they fail**

```bash
pnpm test
```

Expected: the `legacy /verify is gone` test FAILS because `/verify` still returns 400/200/etc. instead of 404. The `GET /healthz` test still passes.

- [ ] **Step 3: Strip `/verify` from `src/app.ts`**

Replace the entire file with:

```ts
import { Hono } from 'hono';

/**
 * Build the Hono app.
 *
 * Factory rather than module-level singleton so tests can construct
 * fresh instances and so server.ts stays a thin entrypoint.
 */
export function createApp(): Hono {
  const app = new Hono();
  app.get('/healthz', (c) => c.json({ status: 'ok' }));
  return app;
}
```

- [ ] **Step 4: Delete the Toss verify adapter**

```bash
git rm src/toss/verify.ts src/toss/verify.test.ts
```

- [ ] **Step 5: Run tests and confirm green**

```bash
pnpm test
```

Expected: both tests pass. No leftover references to `verifyTossAuthorizationCode`.

- [ ] **Step 6: Run lint + typecheck + build**

```bash
pnpm lint && pnpm typecheck && pnpm build
```

Expected: all green. The `dist/` output should still launch via `node dist/server.mjs` and respond to `/healthz`.

- [ ] **Step 7: Commit**

```bash
git add src/app.ts src/app.test.ts
git commit -m "$(cat <<'EOF'
refactor!: delete legacy /verify surface

Zero-code mode replaces the M0 single-endpoint scaffold with a full
OIDC IdP. The /verify route, its Toss adapter, and tests are removed.
Self-host operators of M0/M1 must redeploy fresh; see MIGRATION.md.
EOF
)"
```

The `refactor!:` form signals a breaking change in commit history.

---

## Task 2: Add `MIGRATION.md` for the breaking change

Spec preamble (§1 lead) requires self-host operators to know they cannot upgrade in place.

**Files:**
- Create: `MIGRATION.md` (root)

- [ ] **Step 1: Write `MIGRATION.md`**

```markdown
# Migration — M0 → zero-code mode

The `oidc-bridge` zero-code redesign (May 2026) is **not** backward-compatible
with the M0 `/verify` scaffold. Self-host operators of M0 must redeploy fresh.

## What changed

- `POST /verify` is removed. Mini-apps now call `POST /oidc/token` directly
  (zero-code mode) or via an Edge Function / Cloud Function (confidential
  client mode).
- HTTP Basic Auth against Toss is gone. The bridge now authenticates to
  Toss with mTLS using a per-app cert + key pair issued in the
  Apps-in-Toss console.
- Tenants are now multi-level: `workspace → app`. Each app is one Toss
  mini-app.
- Bridge issues sealed `ait_*` tokens and an RS256 id_token. Operator
  backends never see a Toss `refresh_token`.

## What you need to do

1. Take a backup of any state you care about. M0 had no persistent state;
   you can skip this if you ran the M0 image directly.
2. Pull the new image (or rebuild from source).
3. Run `oidc-bridge bootstrap` to initialize the new SQLite/Postgres
   schema and create your first user, API token, and workspace.
4. Register your mini-app(s) with `oidc-bridge app create` and upload the
   mTLS cert + key from the Apps-in-Toss console.
5. Update your mini-app to call `POST /oidc/token` (zero-code) or your
   Edge Function (confidential).

See `SELF_HOSTING.md` (added in Phase 9) for full setup instructions.
```

- [ ] **Step 2: Commit**

```bash
git add MIGRATION.md
git commit -m "docs: add MIGRATION.md for the zero-code breaking change"
```

---

## Task 3: Install pino + pino-pretty

We pick `pino` for structured logs because it is the de-facto Node.js choice for low-overhead JSON logs, integrates trivially with Cloud Logging (stdout JSON), and supports a static redact list — which we rely on for invariant 4 ("no secrets in logs").

**Files:**
- Modify: `package.json`
- Modify: `pnpm-lock.yaml`

- [ ] **Step 1: Add the dependencies**

```bash
pnpm add pino@^9
pnpm add -D pino-pretty@^11
```

- [ ] **Step 2: Verify installation**

```bash
pnpm list pino pino-pretty --depth=0
```

Expected output mentions `pino 9.x.y` under `dependencies` and `pino-pretty 11.x.y` under `devDependencies`.

- [ ] **Step 3: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: add pino + pino-pretty for structured logging"
```

---

## Task 4: Logger factory with redact list

A single `createLogger()` produces a child logger configured for the runtime mode (pretty in dev, JSON in prod). The redact list is the load-bearing part — every other phase that adds a secret must extend it here.

**Files:**
- Create: `src/logger.ts`
- Create: `src/logger.test.ts`

- [ ] **Step 1: Write the failing test for redaction**

`src/logger.test.ts`:

```ts
import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createLogger } from './logger.js';

function captureLogs(): { stream: Writable; lines: string[] } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(chunk.toString());
      cb();
    },
  });
  return { stream, lines };
}

describe('createLogger', () => {
  it('redacts known secret-named fields', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info(
      {
        client_secret: 'super-secret',
        client_secret_hashes: ['hash1'],
        access_token: 'at_xxx',
        refresh_token: 'rt_xxx',
        ait_access_token: 'ait_xxx',
        ait_refresh_token: 'ait_xxx',
        mtls_cert: '-----BEGIN CERTIFICATE-----',
        mtls_key: '-----BEGIN PRIVATE KEY-----',
        api_token: 'tok_xxx',
        master_key: 'deadbeef',
        password: 'p',
      },
      'log with secrets',
    );

    const line = lines.join('');
    expect(line).not.toContain('super-secret');
    expect(line).not.toContain('hash1');
    expect(line).not.toContain('at_xxx');
    expect(line).not.toContain('rt_xxx');
    expect(line).not.toContain('ait_xxx');
    expect(line).not.toContain('-----BEGIN');
    expect(line).not.toContain('tok_xxx');
    expect(line).not.toContain('deadbeef');
    // Pino's default redacted marker is "[Redacted]".
    expect(line).toContain('[Redacted]');
  });

  it('emits valid JSON in json mode', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });
    log.info({ foo: 'bar' }, 'hello');
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.msg).toBe('hello');
    expect(parsed.foo).toBe('bar');
    expect(parsed.level).toBe(30);
  });
});
```

- [ ] **Step 2: Run test and confirm it fails**

```bash
pnpm test src/logger.test.ts
```

Expected: FAIL with "Cannot find module './logger.js'".

- [ ] **Step 3: Implement `src/logger.ts`**

```ts
import type { Writable } from 'node:stream';
import pino, { type Logger } from 'pino';

export type LoggerMode = 'json' | 'pretty';

export interface CreateLoggerOptions {
  mode?: LoggerMode;
  destination?: Writable;
  level?: pino.Level;
}

const REDACT_PATHS = [
  'client_secret',
  'client_secret_hashes',
  'access_token',
  'refresh_token',
  'ait_access_token',
  'ait_refresh_token',
  'mtls_cert',
  'mtls_key',
  'api_token',
  'master_key',
  'password',
  // Wildcard variants for nested objects.
  '*.client_secret',
  '*.access_token',
  '*.refresh_token',
  '*.ait_access_token',
  '*.ait_refresh_token',
  '*.mtls_cert',
  '*.mtls_key',
  '*.api_token',
  '*.master_key',
];

export function createLogger(opts: CreateLoggerOptions = {}): Logger {
  const mode: LoggerMode = opts.mode ?? (process.env.NODE_ENV === 'production' ? 'json' : 'pretty');
  const level: pino.Level = opts.level ?? (process.env.LOG_LEVEL as pino.Level | undefined) ?? 'info';

  const baseOptions: pino.LoggerOptions = {
    level,
    redact: { paths: REDACT_PATHS, censor: '[Redacted]' },
    base: { service: 'oidc-bridge' },
  };

  // pino-pretty is dev-only and not safe to require in production builds.
  if (mode === 'pretty' && !opts.destination) {
    return pino({
      ...baseOptions,
      transport: {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'SYS:standard' },
      },
    });
  }

  if (opts.destination) {
    return pino(baseOptions, opts.destination);
  }
  return pino(baseOptions);
}
```

- [ ] **Step 4: Run tests and confirm green**

```bash
pnpm test src/logger.test.ts
```

Expected: both tests pass.

- [ ] **Step 5: Run lint + typecheck**

```bash
pnpm lint && pnpm typecheck
```

Expected: green.

- [ ] **Step 6: Commit**

```bash
git add src/logger.ts src/logger.test.ts
git commit -m "feat(logger): pino factory with redact list for known secret fields"
```

---

## Task 5: Wire pino into `server.ts`

`server.ts` becomes the single bootstrap that creates the logger and the app, and logs `serve` lifecycle. We do not yet add per-request logging — that comes in Phase 8 with request-id.

**Files:**
- Modify: `src/server.ts`

- [ ] **Step 1: Replace `src/server.ts`**

```ts
import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { createLogger } from './logger.js';

const log = createLogger();
const port = Number(process.env.PORT ?? 8080);
const app = createApp();

serve({ fetch: app.fetch, port }, (info) => {
  log.info({ port: info.port, addr: info.address }, 'oidc-bridge listening');
});

const shutdown = (signal: NodeJS.Signals) => {
  log.info({ signal }, 'received shutdown signal');
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
```

- [ ] **Step 2: Smoke-test the bootstrap**

```bash
pnpm build
PORT=8081 node dist/server.mjs &
SERVER_PID=$!
sleep 1
curl -fsS http://127.0.0.1:8081/healthz
echo
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true
```

Expected:
- A pino-pretty line on stdout containing `oidc-bridge listening` and `port: 8081`.
- `curl` prints `{"status":"ok"}`.

- [ ] **Step 3: Run lint + typecheck + test**

```bash
pnpm lint && pnpm typecheck && pnpm test
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add src/server.ts
git commit -m "refactor(server): use pino logger; remove console.log"
```

---

## Task 6: Stake out empty module directories

Subsequent phases need stable import paths. Creating placeholder directories now means the file moves in later phases are minimal (one new file each, not "create dir + new file").

**Files:**
- Create: `src/oidc/.gitkeep`
- Create: `src/storage/.gitkeep`
- Create: `src/master-keys/.gitkeep`
- Create: `src/apps/.gitkeep`
- Create: `src/audit/.gitkeep`
- Create: `cli/.gitkeep`

- [ ] **Step 1: Create the directories with `.gitkeep` markers**

```bash
mkdir -p src/oidc src/storage src/master-keys src/apps src/audit cli
touch src/oidc/.gitkeep src/storage/.gitkeep src/master-keys/.gitkeep src/apps/.gitkeep src/audit/.gitkeep cli/.gitkeep
```

(Note: `src/toss/` already exists from before and stays — Phase 5 fills it with the real adapter.)

- [ ] **Step 2: Commit**

```bash
git add src/oidc/.gitkeep src/storage/.gitkeep src/master-keys/.gitkeep src/apps/.gitkeep src/audit/.gitkeep cli/.gitkeep
git commit -m "chore: stake out module directories for later phases"
```

---

## Task 7: Update `tsconfig.json` to include `cli/`

`cli/` is outside `src/`. We extend `include` so the CLI source compiles under the same `tsc --noEmit` invocation, but we keep `rootDir: src` so the build output still maps to `dist/` cleanly. The CLI gets its own build target in Phase 7; for now we only need typecheck coverage.

**Files:**
- Modify: `tsconfig.json`

- [ ] **Step 1: Update tsconfig**

Replace `"include": ["src/**/*"]` with `"include": ["src/**/*", "cli/**/*"]`. Also remove `"rootDir": "src"` — once `cli/` participates, a single `rootDir` no longer applies. tsdown's per-entrypoint compilation does not care; `tsc --noEmit` does not need a rootDir to typecheck.

The full file:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "lib": ["ES2022"],
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "exactOptionalPropertyTypes": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "outDir": "dist"
  },
  "include": ["src/**/*", "cli/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

- [ ] **Step 2: Verify typecheck still green**

```bash
pnpm typecheck
```

Expected: no errors. (Empty `cli/` has nothing to typecheck yet.)

- [ ] **Step 3: Verify build still produces `dist/server.mjs`**

```bash
pnpm build
ls -1 dist/
```

Expected: `dist/server.mjs` exists. Since `cli/` is empty, no CLI artifact is produced — that comes in Phase 7.

- [ ] **Step 4: Commit**

```bash
git add tsconfig.json
git commit -m "chore(tsconfig): include cli/ for typecheck"
```

---

## Task 8: Refresh `README.md`

The current README pitches M0/M1. Reframe it for zero-code mode, link to the spec and index plan. Keep it short — operator-facing detail goes in `SELF_HOSTING.md` (Phase 9).

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace `README.md`**

```markdown
# oidc-bridge

> Community-run OIDC adapter that bridges **Toss login** into BaaS platforms (Supabase, Firebase, Auth0, Keycloak, …).

This is an **unofficial** community project — not affiliated with or endorsed by Toss. The public instance at `oidc-bridge.aitc.dev` is rate-limited and best-effort; security-sensitive workloads should self-host.

## What it does

A mini-app developer registers their app with the Bridge and gets a `client_id` + an `iss = https://oidc-bridge.aitc.dev` OIDC issuer URL. The mini-app calls `appLogin()` to get a Toss `authorizationCode`, exchanges it at `POST /oidc/token` for an OIDC `id_token`, and signs into Supabase via `signInWithIdToken`. No backend code required (zero-code mode).

For Edge Function / Cloud Function operators that want server authority, the same `/oidc/token` endpoint accepts `client_secret` authentication (confidential-client mode).

## Status

Zero-code mode is under active implementation as of May 2026. See:

- [Design spec](docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) — full architecture, components, security model.
- [Implementation index](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md) — phase-by-phase plan.
- [`MIGRATION.md`](./MIGRATION.md) — breaking change from M0.

## Self-host

Self-hosting docs (`SELF_HOSTING.md`) ship in Phase 9 of the implementation plan. Until then, this repo is not yet runnable as a multi-tenant production service.

## License

BSD-3-Clause. See `LICENSE`.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs(README): reframe for zero-code mode; link spec + plan"
```

---

## Task 9: Final phase-end verification

Before declaring Phase 0 done, run the full local pipeline and confirm everything green.

- [ ] **Step 1: Full local pipeline**

```bash
pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm build && pnpm test
```

Expected: every step green, no warnings, no failing tests.

- [ ] **Step 2: Docker smoke test**

```bash
docker build -t oidc-bridge:phase0 .
docker run -d --name oidc-bridge-phase0 -p 127.0.0.1:8082:8080 oidc-bridge:phase0
sleep 2
curl -fsS http://127.0.0.1:8082/healthz
echo
docker logs oidc-bridge-phase0 | tail -5
docker rm -f oidc-bridge-phase0
```

Expected:
- `curl` prints `{"status":"ok"}`.
- `docker logs` shows a JSON line with `"msg":"oidc-bridge listening"` (production mode picks `json` log mode).

- [ ] **Step 3: Confirm no leftover legacy code**

```bash
git grep -nE 'verifyTossAuthorizationCode|/verify' src/ cli/
```

Expected: empty output (nothing matches).

```bash
git grep -nE 'TOSS_CLIENT_ID|TOSS_CLIENT_SECRET' src/ cli/ Dockerfile docker-compose.yml
```

Expected: empty output. (M0 used HTTP Basic Auth env vars; zero-code uses per-app mTLS, which Phase 5 introduces.)

- [ ] **Step 4: Confirm CI workflow still green**

If pushing to GitHub at this point: open a draft PR titled `Phase 0: skeleton` and confirm CI is green. If working in a worktree without pushing yet, skip.

- [ ] **Step 5: Mark Phase 0 complete**

Move to the [Phase 1 plan](./2026-05-01-zero-code-phase-01-db-master-keys.md) (authored when Phase 0 is approved for handoff). Phase 0 produces no merge to `main`; the integration branch `zero-code-mode` accumulates phases.

---

## Phase 0 — done condition

After Task 9 passes, the following are true:

- `GET /healthz` returns `{status:"ok"}`. No other route exists.
- `pnpm lint && pnpm typecheck && pnpm build && pnpm test` is green.
- `docker build && docker run` produces a healthy container.
- Pino emits structured JSON in production and pretty output in dev.
- The redact list covers all known secret field names from the spec.
- `src/oidc/`, `src/toss/`, `src/storage/`, `src/master-keys/`, `src/apps/`, `src/audit/`, `cli/` exist as empty (or `.gitkeep`-marked) directories.
- `MIGRATION.md` and `README.md` reflect the zero-code reframing.
- No legacy `/verify`, `verifyTossAuthorizationCode`, or `TOSS_CLIENT_*` env references remain.

That state is the foundation Phase 1 builds on.
