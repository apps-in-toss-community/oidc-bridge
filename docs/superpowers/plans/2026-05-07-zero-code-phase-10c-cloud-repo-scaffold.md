# oidc-bridge zero-code mode — Phase 10c: `oidc-bridge-cloud` private repo scaffold

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the new private repo `apps-in-toss-community/oidc-bridge-cloud` with the **dispatcher Worker scaffold**, **admin endpoint stubs**, **Cloudflare API client (account-aware)**, and **tenant registry D1 schema**. **No production deploy in this phase.** The output is a repo whose `pnpm typecheck && pnpm lint && pnpm test` is green and whose `wrangler deploy --dry-run` succeeds locally; live wrangler deploys happen in Phase 11c (canary tenant).

**Why a separate private repo:** Spec [`docs/superpowers/specs/2026-05-07-cloudflare-cloud-separation.md`](../specs/2026-05-07-cloudflare-cloud-separation.md) §6.1 — the cloud control plane encodes operator-specific secrets and CF-account-level config (account id, dispatch namespace name, D1 naming convention, API token issuance flow). The OSS surface stays in the public `oidc-bridge` repo (self-host path). Holding the dispatcher private also avoids leaking the tenant routing scheme to scrapers before the model has been hardened.

**Architecture (Worker-side):** Single dispatcher Worker on `oidc-bridge.aitc.dev` (DNS not yet cut over — that's Phase 13c). The dispatcher's job is path-prefix routing to per-tenant Workers in the `oidc-bridge` dispatch namespace. Routing key: `/t/<tenantId>/...` (Spec §11 Q2 resolved here for 10c — hostname routing remains a follow-up; switching is a router-level change once tenant Workers exist in 11c). Admin endpoints live at `/admin/*` on the dispatcher itself (not delegated to a tenant). The CF API client wraps cert upload, Worker PUT (script + metadata), D1 CRUD; it is **account-aware from day 1** so multi-account sharding (Spec §7.2) is a router-level change later, never a rewrite. The tenant registry D1 lives on the dispatcher's own D1 binding (`REGISTRY_DB`), schema in §4.1 of the spec, with `cf_account_id TEXT NOT NULL` baked in.

**Architecture (oidc-bridge dependency):** The dispatcher does not yet route to tenant Workers (no tenant Workers exist before Phase 11c). All routes that would land on a tenant Worker return `503 tenant_worker_not_provisioned` with a structured body that names the tenant and its expected provisioning phase. This makes 10c testable end-to-end through `miniflare` without a single live Worker. The `oidc-bridge` repo gets **no code changes** in this phase — Phase 09c already produced the runtime-agnostic core that the tenant Worker template (Phase 11c) will consume.

**Tech stack:** TypeScript ESM strict, Hono (already runtime-agnostic), `wrangler` 3.x (Cloudflare Workers CLI), `drizzle-orm/d1` (registry storage), `miniflare` 4 (in-process testing — same harness that Phase 09c proved), `@cloudflare/workers-types` (type-only, dev), `vitest` (mirroring `oidc-bridge` repo conventions). No `node:*` imports anywhere in `src/`. No `process.env` reads anywhere in `src/`. The CF API client uses `fetch` against `api.cloudflare.com` directly (no `cloudflare` SDK — that npm package adds a Node-only crypto dep that breaks Workers bundling).

**Auth:** Admin auth = bearer token (Spec §11 Q3 resolved here for 10c — same pattern as `oidc-bridge` Phase 2 admin REST). The token lives in Workers Secrets as `ADMIN_BEARER_TOKEN`, issued out-of-band by the operator. mTLS-client-cert admin auth remains a follow-up. Ops-laptop CF API token (cert-write scope) is `CF_API_TOKEN` Workers Secret; runtime read-only token (registry D1 + Worker introspection) would be split in Phase 12c+ when cert rotation lands — for 10c the dispatcher uses one token bound to its lowest-privilege scope (account read + D1 write only; no `mtls_certificates:write`).

---

## Universal invariants (apply to every task)

1. **No production deploy.** Phase 10c output is code + tests + `wrangler dev` + `wrangler deploy --dry-run` only. Real deploys are Phase 11c (canary tenant). Even DNS for `oidc-bridge.aitc.dev` is not touched.
2. **No `oidc-bridge` repo changes.** This phase lives entirely in the new `oidc-bridge-cloud` repo. If a code change in `oidc-bridge` is genuinely needed (e.g. a missing export), defer it to a follow-up PR on that repo and unblock 10c by inlining locally first; flag the gap in the final summary.
3. **TDD.** Failing test → minimal code → green → commit. Conventional Commits.
4. **No `node:*` imports in `src/`.** `node:crypto`, `node:tls`, `node:fs`, `node:path` all forbidden. Use WebCrypto, `URL`, `TextEncoder`/`TextDecoder`. Test files (which run on Node via vitest) may import `node:test-helpers` if needed but should prefer the Workers-compatible path.
5. **No `process.env` reads in `src/`.** Workers env arrives as the second `fetch` parameter; pass it through. (Phase 09c retro standing decision.)
6. **`Buffer` forbidden in `src/`.** Use `Uint8Array`. (Phase 09c retro standing decision.)
7. **`@cloudflare/workers-types` is type-only.** No `/// <reference types="..." />` directives — they globally pollute and break `tsconfig` `types: ["node"]`. Use `import type { D1Database, ExecutionContext, MTlsCertificateBinding } from '@cloudflare/workers-types'` per file.
8. **CF API client is account-aware.** Every method takes `accountId` as input. There is no global "the account" anywhere — the dispatcher resolves `accountId` from the tenant registry per request. (Spec §7.2 multi-account sharding readiness.)
9. **`cf_account_id` is NOT NULL from day 1** in the `tenants` table. Migration won't backfill later.
10. **Admin endpoints are stubs.** They validate the bearer, validate input shape, and return a structured `not_implemented_phase_11c` (or 12c) response with the body shape that the real impl will use. No CF API calls are made for admin operations in this phase — the CF API client is wired but only exercised by tests with a fake fetch.
11. **D1 quirks** (Phase 09c retro): no `IF NOT EXISTS` on DDL, no `DESC` in expression indexes. Migrations use plain `CREATE TABLE` and a state-check guard.
12. **Dispatcher-side rate limit + request-id.** Reuse the patterns from `oidc-bridge` Phase 8 — but the implementations are reimplemented here (different middleware shape on Workers). Cross-runtime byte-equal tests (Phase 09c standing decision) where feasible.
13. **No emojis.** Repo is operator-facing internal tooling.
14. **Brand:** `oidc-bridge-cloud` is the **community (unofficial)** project's operator-private control plane. README must say so explicitly. No "official", "powered by Toss".
15. **Lint + typecheck + test pass on every commit.** `pnpm typecheck && pnpm lint && pnpm test` is the gate. Additionally `pnpm wrangler deploy --dry-run --env staging` must succeed.

## Files this phase creates (the entire `oidc-bridge-cloud` repo)

```
oidc-bridge-cloud/
├─ .github/
│  ├─ workflows/
│  │  └─ ci.yml              # NEW — typecheck + lint + test + wrangler dry-run
│  └─ CODEOWNERS              # NEW — operator-only
├─ .githooks/
│  └─ pre-commit              # NEW — mirrors oidc-bridge pre-commit (biome check + typecheck)
├─ src/
│  ├─ dispatcher.ts           # NEW — Hono app: routing + admin mount; default Workers fetch handler
│  ├─ runtime/
│  │  ├─ env.ts               # NEW — typed Env interface (DB, KV, secrets, namespaces)
│  │  └─ context.ts           # NEW — per-request context (logger, traceId, env)
│  ├─ admin/
│  │  ├─ auth.ts              # NEW — bearer auth middleware
│  │  ├─ tenants.ts           # NEW — POST/GET/DELETE /admin/tenants[/...] stubs
│  │  ├─ rotation.ts          # NEW — POST /admin/tenants/:id/rotate stub (Phase 12c)
│  │  ├─ cf-api.ts            # NEW — CFApiClient (account-aware factory)
│  │  └─ registry.ts          # NEW — TenantRegistry (drizzle-orm/d1)
│  ├─ routing/
│  │  ├─ tenant-resolver.ts   # NEW — path-prefix /t/<id>/... → tenant lookup
│  │  └─ dispatch.ts          # NEW — env.NS.get(workerName).fetch() with 503-when-absent
│  ├─ schema/
│  │  └─ d1.ts                # NEW — drizzle schema for the dispatcher's D1
│  ├─ middleware/
│  │  ├─ request-id.ts        # NEW — same shape as oidc-bridge phase 8, Workers-flavored
│  │  ├─ rate-limit.ts        # NEW — sliding window via Workers Cache API; in-memory fallback for tests
│  │  └─ logger.ts            # NEW — JSON-line console.log; same redact list as oidc-bridge node-logger
│  ├─ errors/
│  │  └─ structured.ts        # NEW — { error, error_description, traceId } body factory
│  └─ index.ts                # NEW — re-export dispatcher as default Workers fetch handler
├─ migrations/
│  └─ 0001_init.sql           # NEW — tenants + audit_log tables
├─ test/
│  ├─ dispatcher.test.ts      # NEW — Hono app.request() smoke through miniflare
│  ├─ admin/
│  │  ├─ auth.test.ts         # NEW
│  │  ├─ tenants.test.ts      # NEW — stubs return not_implemented with correct body shape
│  │  └─ cf-api.test.ts       # NEW — fakeFetch verifies request shape against CF API spec
│  ├─ routing/
│  │  └─ tenant-resolver.test.ts # NEW
│  ├─ schema/
│  │  └─ migrations.test.ts   # NEW — runStorageConformance subset (we don't have full sessions/refresh tokens here, only registry+audit)
│  └─ helpers/
│     ├─ miniflare.ts         # NEW — test bootstrapper
│     └─ fake-fetch.ts        # NEW — fetch stub for CF API
├─ wrangler.toml              # NEW — dispatcher config + dispatch_namespace + bindings + envs
├─ tsconfig.json              # NEW — strict, types: ["node", "@cloudflare/workers-types"]
├─ biome.json                 # NEW — same rules as oidc-bridge
├─ package.json               # NEW — pnpm 10.33.0, scripts mirror oidc-bridge
├─ pnpm-lock.yaml             # NEW — committed
├─ drizzle.config.ts          # NEW — D1 dialect, points at schema/d1.ts and migrations/
├─ .gitignore                 # NEW — node_modules, .wrangler/, dist/, .env*
├─ .env.example               # NEW — documents every Worker secret + binding (no values)
├─ CLAUDE.md                  # NEW — repo-specific Claude guide (mirrors oidc-bridge style: brand, scope, commands, standing decisions inherited from 09c)
├─ README.md                  # NEW — operator-only quickstart
└─ SECURITY.md                # NEW — describes secret-token model, ops laptop expectations
```

The `oidc-bridge` (public) repo gets **zero changes** in this PR. Any cross-repo follow-up (e.g. exporting an internal helper for reuse) is filed as a separate `oidc-bridge` PR with `chore: expose X for oidc-bridge-cloud` after 10c lands.

## Pre-flight (do this once before Task 1)

```bash
# In ~/Projects/github.com/apps-in-toss-community/
gh repo clone apps-in-toss-community/oidc-bridge-cloud
cd oidc-bridge-cloud
git checkout -b feat/zero-code-phase-10c-scaffold
```

The repo is created (private) by the operator out-of-band before this plan runs:

```bash
gh repo create apps-in-toss-community/oidc-bridge-cloud --private \
  --description "Cloudflare Workers control plane (operator-private; OSS path is github.com/apps-in-toss-community/oidc-bridge)"
```

Cloudflare account access (already provisioned for the prototype):

- `wrangler whoami` succeeds and shows the operator's account.
- The dispatch namespace `oidc-bridge` exists (created during prototype validation; if missing, `wrangler dispatch-namespace create oidc-bridge`).
- A staging D1 named `oidc-bridge-registry-staging` exists (used for `wrangler dev`/local smoke).

If `wrangler whoami` fails or the namespace is missing, **stop**. The operator must fix that out-of-band before Task 1.

This phase **depends on**:

- Spec §3 (two-layer Worker model), §4 (control plane), §6.1 (repo skeleton), §7.2 (multi-account sharding readiness baked in), §11 Q2/Q3 (decisions made in this phase preamble: path prefix; bearer admin).
- Phase 09c standing decisions section in `oidc-bridge` `CLAUDE.md` (Workers env model, byte purity, async crypto, golden vectors). Re-read before Task 1.
- Phase 09c retro lessons (`oidc-bridge/docs/superpowers/retros/2026-05-07-phase-09c-retro.md`): D1 quirks, type-only Workers types, `process.env` purity, deliberate `temporarily_unavailable` 501 pattern. The 10c equivalent is `503 tenant_worker_not_provisioned` for tenant routes.

This phase **does not depend on** any code in the `oidc-bridge` repo as a runtime import — Phase 11c is when the tenant Worker template starts importing `oidc-bridge`'s runtime-agnostic core via published artifact (or git subtree, decision deferred to 11c).

---

## Task 1: Bootstrap repo (`package.json`, `tsconfig.json`, `biome.json`, `.gitignore`)

**Files:**
- Create: `package.json`, `tsconfig.json`, `biome.json`, `.gitignore`, `.env.example`, `pnpm-lock.yaml`

Mirror `oidc-bridge`'s `package.json` skeleton (Node 24, pnpm 10.33.0, biome, vitest, tsdown), but with Workers-specific extras: `wrangler` (devDep), `@cloudflare/workers-types` (devDep), `miniflare` (devDep), `drizzle-orm` + `drizzle-kit` (deps; `better-sqlite3` is **not** a dep here — D1 only). Hono is a runtime dep.

- [ ] **Step 1**: scaffold `package.json` with scripts:

  ```jsonc
  {
    "scripts": {
      "dev": "wrangler dev",
      "build": "wrangler deploy --dry-run --outdir=dist",
      "typecheck": "tsc --noEmit",
      "lint": "biome check .",
      "lint:fix": "biome check --write .",
      "format": "biome format --write .",
      "test": "vitest run",
      "test:watch": "vitest",
      "db:generate": "drizzle-kit generate --config drizzle.config.ts",
      "db:migrate:local": "wrangler d1 migrations apply oidc-bridge-registry-staging --local"
    }
  }
  ```

- [ ] **Step 2**: `tsconfig.json` strict + `types: ["node", "@cloudflare/workers-types"]`. Module = `ESNext`, moduleResolution = `Bundler`.

- [ ] **Step 3**: `biome.json` copies `oidc-bridge`'s rules verbatim. `noExplicitAny: error` is mandatory.

- [ ] **Step 4**: `.gitignore` covers `node_modules`, `.wrangler/`, `dist/`, `.env*`, `.dev.vars`, `*.log`.

- [ ] **Step 5**: `.env.example` documents every Workers Secret + binding by name, with descriptions, no values:

  ```
  ADMIN_BEARER_TOKEN=         # Operator-facing admin auth bearer (rotated quarterly)
  CF_API_TOKEN=               # CF API token; account read + D1 write scope only in 10c
  ```

- [ ] **Step 6**: `pnpm install`, commit lockfile and the four scaffolding files.

- [ ] **Commit:** `chore: bootstrap pnpm workspace + tsconfig + biome (Workers + D1 stack)`

---

## Task 2: `wrangler.toml` + envs (staging, production)

**Files:**
- Create: `wrangler.toml`

Defines:
- Worker name: `oidc-bridge-dispatcher`
- `compatibility_date = "2026-05-07"` (current).
- `[env.staging]` + `[env.production]` blocks. Bindings declared per-env:
  - `[[env.staging.d1_databases]]` → `binding = "REGISTRY_DB"`, `database_name = "oidc-bridge-registry-staging"`, `database_id` placeholder filled by operator out-of-band.
  - `[[env.staging.dispatch_namespaces]]` → `binding = "NS"`, `namespace = "oidc-bridge"`.
  - `[env.staging.vars]` → `LOG_LEVEL = "info"`.
  - secrets are **not** declared here (they're set via `wrangler secret put`).
- No `[env.production]` `database_id` for now — set out-of-band before Phase 11c. Document the missing values clearly in a comment.

- [ ] **Step 1**: Author `wrangler.toml`. Be explicit that secrets `ADMIN_BEARER_TOKEN` + `CF_API_TOKEN` are set via `wrangler secret put` per env.

- [ ] **Step 2**: Run `wrangler deploy --dry-run --env staging` from local. Should succeed (binds to D1 ID placeholder is OK for dry-run because `--dry-run` skips actual binding resolution).

- [ ] **Step 3**: Add a `.dev.vars.example` for local `wrangler dev` smoke. Real `.dev.vars` is gitignored.

- [ ] **Commit:** `chore(wrangler): dispatcher worker + staging/production env shells`

---

## Task 3: `Env` typing + per-request context

**Files:**
- Create: `src/runtime/env.ts`, `src/runtime/context.ts`, `src/runtime/env.test.ts`

`Env` is the canonical typed shape of `env` passed into every Workers `fetch`. Drift between this and `wrangler.toml` is the #1 cloud-side bug source — keep it tight:

```ts
import type { D1Database, DispatchNamespace } from '@cloudflare/workers-types';

export interface Env {
  REGISTRY_DB: D1Database;
  NS: DispatchNamespace;
  ADMIN_BEARER_TOKEN: string;     // secret_text
  CF_API_TOKEN: string;           // secret_text
  CF_ACCOUNT_ID: string;          // var (account id of the primary account; per-tenant overrides come from the registry, see §7.2)
  LOG_LEVEL: 'debug' | 'info' | 'warn' | 'error';
}
```

Per-request `Context` builds a logger child with `traceId`, holds `env`, holds an injected `now: () => Date` for deterministic tests.

- [ ] **Step 1**: Failing test that imports `Env` and asserts the type shape via `expectTypeOf` (vitest `expect-type` helper).

- [ ] **Step 2**: Implement `Env` interface and `createContext({ env, request })` in `context.ts`.

- [ ] **Step 3**: Tests for `createContext`: traceId is a uuid, logger is a child with `traceId` bound, `now()` is plumbed.

- [ ] **Commit:** `feat(runtime): typed Env + per-request Context with traceId`

---

## Task 4: Logger (Workers JSON-line) + redact list

**Files:**
- Create: `src/middleware/logger.ts`, `src/middleware/logger.test.ts`

Mirrors `oidc-bridge/src/runtime/workers-logger.ts` (Phase 09c). Same redact key list. JSON-line `console.log` output with `level`, `time`, `msg`, plus arbitrary fields. `child(bindings)` returns a new logger whose every line gets bindings merged in.

- [ ] **Step 1**: Failing test: a logger instance produces a single line of valid JSON, with redacted keys masked as `[REDACTED]`. Asserts the redact list includes (at minimum): `mtls_cert_pem`, `mtls_key_pem`, `toss_access_token`, `refresh_token`, `client_secret`, `authorization`, `cookie`.

- [ ] **Step 2**: Implement `createLogger({ level, redact })`.

- [ ] **Step 3**: Verify `child(bindings)` propagates redact list (regression-prone area per Phase 09c retro).

- [ ] **Commit:** `feat(middleware): JSON-line Workers logger with redact list`

---

## Task 5: D1 schema + migration `0001_init.sql`

**Files:**
- Create: `src/schema/d1.ts`, `migrations/0001_init.sql`, `drizzle.config.ts`, `test/schema/migrations.test.ts`, `test/helpers/miniflare.ts`

Two tables:

```sql
CREATE TABLE tenants (
  tenant_id          TEXT PRIMARY KEY,
  display_name       TEXT NOT NULL,
  cf_account_id      TEXT NOT NULL,
  worker_name        TEXT NOT NULL,
  active_cert_binding TEXT NOT NULL DEFAULT 'TOSS_MTLS',
  active_cf_cert_id  TEXT NOT NULL DEFAULT '',
  rotation_state     TEXT NOT NULL DEFAULT 'idle',
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);

CREATE INDEX tenants_cf_account_idx ON tenants (cf_account_id);

CREATE TABLE audit_log (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT,                      -- nullable: dispatcher-level events
  actor        TEXT NOT NULL,             -- e.g. "admin:bearer:DaveDev42"
  action       TEXT NOT NULL,             -- "tenants.create", "rotation.overlap", ...
  payload_json TEXT NOT NULL DEFAULT '{}',
  outcome      TEXT NOT NULL,             -- "ok" | "error:<code>"
  created_at   INTEGER NOT NULL
);

CREATE INDEX audit_log_tenant_created_idx ON audit_log (tenant_id, created_at);
```

D1 quirks (Phase 09c retro): no `IF NOT EXISTS`; no `DESC` in expression indexes (we don't use any here, but document the constraint in a comment).

- [ ] **Step 1**: `drizzle.config.ts` with D1 dialect.

- [ ] **Step 2**: `src/schema/d1.ts` — drizzle table definitions matching the SQL.

- [ ] **Step 3**: `migrations/0001_init.sql` — generated by `pnpm db:generate`, then hand-edited to remove any `IF NOT EXISTS` and ensure ASC indexes.

- [ ] **Step 4**: `test/helpers/miniflare.ts` — bootstraps a miniflare 4 in-memory D1 with the migration applied.

- [ ] **Step 5**: `test/schema/migrations.test.ts` — applies migration to fresh D1, runs INSERT/SELECT round-trips on both tables, verifies the `cf_account_id` index is used (`EXPLAIN QUERY PLAN`).

- [ ] **Step 6**: `pnpm test`, expect green.

- [ ] **Commit:** `feat(schema): tenants + audit_log D1 tables (cf_account_id NOT NULL from day 1)`

---

## Task 6: `TenantRegistry` (drizzle wrapper)

**Files:**
- Create: `src/admin/registry.ts`, `test/admin/registry.test.ts`

Exposes:
```ts
interface TenantRegistry {
  getByTenantId(id: string): Promise<TenantRow | null>;
  list(opts?: { cfAccountId?: string }): Promise<TenantRow[]>;
  insert(row: TenantInsert): Promise<void>;
  updateRotationState(id: string, next: RotationState): Promise<void>;
  recordAudit(entry: AuditInsert): Promise<void>;
}
```

- [ ] **Step 1**: Tests run against miniflare D1 with seed rows. Insert + getByTenantId round-trip; list filtered by cfAccountId; rotation state transitions are arbitrary text (no enum check at the DB layer — application layer guards).

- [ ] **Step 2**: Implement using `drizzle-orm/d1`.

- [ ] **Commit:** `feat(admin): TenantRegistry with miniflare D1 conformance`

---

## Task 7: `CFApiClient` (account-aware, fetch-only)

**Files:**
- Create: `src/admin/cf-api.ts`, `test/admin/cf-api.test.ts`, `test/helpers/fake-fetch.ts`

Critical: this is **the** invariant for multi-account sharding readiness (Spec §7.2). Every method takes `accountId` as input. There is no global "primary account" buried inside the client.

```ts
interface CFApiClient {
  uploadMtlsCertificate(opts: {
    accountId: string;
    name: string;
    certPem: string;
    keyPem: string;
  }): Promise<{ id: string }>;

  deleteMtlsCertificate(opts: { accountId: string; id: string }): Promise<void>;

  putWorkerScript(opts: {
    accountId: string;
    namespace: string;
    workerName: string;
    metadata: WorkerMetadata; // bindings list, see Worker metadata API
    script: string;           // ESM source
  }): Promise<void>;

  d1ListTables(opts: { accountId: string; databaseId: string }): Promise<string[]>;
}
```

Implementation: pure `fetch` against `https://api.cloudflare.com/client/v4/accounts/{accountId}/...`. No third-party SDK. Auth via `Authorization: Bearer ${cfApiToken}`. Errors mapped to `CFApiError` with `code` from response body.

- [ ] **Step 1**: Failing tests using `fakeFetch` — assert URL, method, headers, body shape match Cloudflare's API documentation for each method. Reference: prototype evidence doc §3 (we already have `cf_curl_*.sh` shells from prototype validation; mirror those request shapes).

- [ ] **Step 2**: Implement.

- [ ] **Step 3**: Cross-method test: `uploadMtlsCertificate` then `deleteMtlsCertificate(id)` against fakeFetch — verify both account ids are passed correctly and could be different (proves account-aware-ness).

- [ ] **Commit:** `feat(admin): account-aware CFApiClient (cert upload, worker put, d1 introspect)`

---

## Task 8: Admin auth middleware (bearer)

**Files:**
- Create: `src/admin/auth.ts`, `test/admin/auth.test.ts`

Hono middleware:
1. Reject if `Authorization` header missing or not `Bearer <token>`.
2. Constant-time compare `token === env.ADMIN_BEARER_TOKEN`.
3. On success, set `c.set('actor', 'admin:bearer')` for downstream audit logging.
4. On failure, return `401 unauthorized` with structured body, log a redacted attempt.

- [ ] **Step 1**: Failing tests for: missing header → 401; wrong token → 401; correct token → 200 + actor set.

- [ ] **Step 2**: Implement constant-time compare via WebCrypto: `crypto.subtle.timingSafeEqual` doesn't exist; reuse the byte-equal helper from `oidc-bridge/src/core/bytes.ts` pattern (a constant-time loop over `Uint8Array`).

- [ ] **Commit:** `feat(admin): bearer auth middleware (constant-time compare)`

---

## Task 9: Admin route stubs (`/admin/tenants/*`, `/admin/tenants/:id/rotate`)

**Files:**
- Create: `src/admin/tenants.ts`, `src/admin/rotation.ts`, `test/admin/tenants.test.ts`

Each handler:
- validates input shape via zod (or hand-rolled validators if no zod dep wanted — match `oidc-bridge` choice).
- writes an audit log entry via `TenantRegistry.recordAudit` for every accepted call.
- returns `501 not_implemented_phase_<n>c` with structured body and the **proposed real response shape** in the body's `_future` field. This makes the contract for Phase 11c/12c implementers explicit.

Endpoints (all stubs):
- `POST /admin/tenants` → `not_implemented_phase_11c`
- `GET /admin/tenants` → **implemented**: returns `await registry.list()` (read-only, safe in 10c).
- `GET /admin/tenants/:id` → **implemented**: returns `await registry.getByTenantId(id)` or 404.
- `DELETE /admin/tenants/:id` → `not_implemented_phase_11c`
- `POST /admin/tenants/:id/cert/upload` → `not_implemented_phase_12c`
- `POST /admin/tenants/:id/rotate` → `not_implemented_phase_12c`

The two `GET` endpoints exercise the registry path end-to-end. They're useful for operator smoke ("which tenants exist?") and they de-risk the registry adapter.

- [ ] **Step 1**: Tests for each endpoint: bearer-protected, body shape correct, audit entry written. Stubs return 501 with `_future` field describing the future shape.

- [ ] **Step 2**: GET endpoints exercise miniflare D1 with seeded rows.

- [ ] **Step 3**: Implement.

- [ ] **Commit:** `feat(admin): tenant CRUD route stubs + GET implementations`

---

## Task 10: Tenant resolver + dispatch routing (with 503 fallback)

**Files:**
- Create: `src/routing/tenant-resolver.ts`, `src/routing/dispatch.ts`, `test/routing/tenant-resolver.test.ts`

`tenant-resolver.ts`:
- Input: `Request` whose URL pathname starts with `/t/<tenantId>/...`
- Output: `{ tenantId, restPath, query }` or `null` if pathname doesn't match.

`dispatch.ts`:
- Given a resolved `tenantId`, look up the registry → `worker_name`.
- If registry has no row for `tenantId`: return structured `503 tenant_worker_not_provisioned` with body `{ error, error_description, tenantId, expected_phase: "11c" }`.
- If registry has a row: call `env.NS.get(workerName).fetch(tenantRequest)` and stream back. **Phase 10c does not yet have a tenant Worker template, so any test in this task that simulates a "registry has row, NS has Worker" path must use a miniflare-mocked dispatch namespace whose `.get(name).fetch(req)` returns a stub response.** This proves the dispatch path is wired.

- [ ] **Step 1**: Tests: pathname `/t/foo/oidc/token` → `{ tenantId: "foo", restPath: "/oidc/token" }`. Pathname `/admin/x` → `null`. Pathname `/t//x` → 400.

- [ ] **Step 2**: Implement resolver.

- [ ] **Step 3**: Dispatch path test: registry empty → 503; registry seeded → calls miniflare-stub fetch → response passes through.

- [ ] **Step 4**: Implement dispatch.

- [ ] **Commit:** `feat(routing): path-prefix tenant resolver + dispatch with 503 fallback`

---

## Task 11: Request-id + rate-limit middleware

**Files:**
- Create: `src/middleware/request-id.ts`, `src/middleware/rate-limit.ts`, tests

Mirror Phase 8 from `oidc-bridge`, Workers-flavored:
- `request-id`: generate `crypto.randomUUID()` if `x-request-id` not present, attach to context, echo in response.
- `rate-limit`: **per-IP sliding window**. Implementation choice: in-memory `Map<ip, timestamps[]>` is **wrong on Workers** (per-isolate, not durable). Use the Workers Cache API as a counter store, or punt: 10c rate-limit is **not enforced**, just measured (counter increments to a Map for tests; in production it's a no-op). Document the no-op clearly. Phase 12c+ either wires Durable Objects or accepts the per-isolate approximation.

- [ ] **Step 1**: Tests for `request-id` (echo + generate).

- [ ] **Step 2**: Tests for `rate-limit`: counts requests per IP within window, returns 429 only when configured `enforce: true` (off in 10c production env).

- [ ] **Step 3**: Implement both.

- [ ] **Commit:** `feat(middleware): request-id + rate-limit (10c: rate-limit measured, not enforced)`

---

## Task 12: Dispatcher Hono app + default fetch handler

**Files:**
- Create: `src/dispatcher.ts`, `src/index.ts`, `test/dispatcher.test.ts`

Composes everything:

```ts
const app = new Hono<{ Bindings: Env; Variables: ContextVars }>();
app.use('*', requestIdMiddleware());
app.use('*', loggerMiddleware());
app.use('*', rateLimitMiddleware({ enforce: false }));

app.route('/admin', adminRoutes);  // bearer-protected inside

// Tenant routing
app.all('/t/:tenantId/*', async (c) => {
  // resolve, dispatch
});

// Health + meta
app.get('/healthz', (c) => c.text('ok'));
app.get('/.well-known/cloud-info', (c) => c.json({
  community: 'apps-in-toss-community (unofficial)',
  phase: '10c',
}));

// 404 + 500 handlers with structured bodies

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext) {
    return app.fetch(req, env, ctx);
  },
};
```

- [ ] **Step 1**: `test/dispatcher.test.ts` smoke: `/healthz` → 200; `/admin/tenants` (no bearer) → 401; `/admin/tenants` (bearer) → 200 + empty list; `/t/unknown/oidc/token` → 503; unknown route → 404 with structured body.

- [ ] **Step 2**: Implement `dispatcher.ts`.

- [ ] **Step 3**: `src/index.ts` re-exports the default Workers handler.

- [ ] **Step 4**: `wrangler dev` smoke (manual): the operator runs `pnpm wrangler dev --env staging`, hits `curl http://localhost:8787/healthz` and `curl -H "Authorization: Bearer <token>" http://localhost:8787/admin/tenants`. Both succeed.

- [ ] **Commit:** `feat(dispatcher): Hono app + default Workers fetch handler`

---

## Task 13: CI (`.github/workflows/ci.yml`) + repo housekeeping

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/CODEOWNERS`, `CLAUDE.md`, `README.md`, `SECURITY.md`, `.githooks/pre-commit`

CI runs on PR + push to main:
- `pnpm install`
- `pnpm typecheck`
- `pnpm lint`
- `pnpm test`
- `pnpm wrangler deploy --dry-run --env staging` (sanity, ensures `wrangler.toml` doesn't drift from `Env`)

`CLAUDE.md` mirrors `oidc-bridge/CLAUDE.md` shape with sections:
- Project nature (community/unofficial), brand bans
- Pair repo: `oidc-bridge` (public OSS — runtime-agnostic core), points to spec
- Architecture summary (one paragraph) — points to spec for detail
- Standing decisions: inherit Phase 09c list (Workers env model, byte purity, async crypto, type-only `@cloudflare/workers-types`, no `process.env`, D1 quirks), plus Phase 10c additions:
  - Path-prefix tenant routing (`/t/<id>/...`)
  - Bearer admin auth (rotated quarterly)
  - `cf_account_id NOT NULL` from day 1
  - CFApiClient is account-aware (no global "the account")
- Commands (`pnpm dev`, `pnpm test`, `pnpm wrangler deploy --dry-run --env staging`)
- Phase index pointing back to `oidc-bridge/docs/superpowers/plans/2026-05-XX-...-10c-...md` (this plan)

`README.md` is short, operator-facing: "This is the operator-private control plane for the **community (unofficial)** apps-in-toss-community oidc-bridge. The OSS path is github.com/apps-in-toss-community/oidc-bridge." + a quickstart pointing to `wrangler dev`.

`SECURITY.md` describes:
- Workers Secrets (`ADMIN_BEARER_TOKEN`, `CF_API_TOKEN`) lifecycle
- Ops laptop expectations (Touch ID, 1Password, no token in env)
- Audit log location

`.githooks/pre-commit` mirrors `oidc-bridge`'s pre-commit (biome check on staged + typecheck quick path).

- [ ] **Step 1**: Author all docs.

- [ ] **Step 2**: CI workflow author + push to a temp branch to verify it runs green.

- [ ] **Commit:** `chore: CI + CLAUDE.md + README + SECURITY + pre-commit hook`

---

## Task 14: Final verification + open PR

- [ ] **Step 1: Run full gate.**

  ```bash
  pnpm typecheck && pnpm lint && pnpm test
  pnpm wrangler deploy --dry-run --env staging
  ```

- [ ] **Step 2: Manual smoke.**

  ```bash
  pnpm wrangler dev --env staging
  # In another terminal:
  curl -s http://localhost:8787/healthz
  curl -s http://localhost:8787/.well-known/cloud-info | jq .
  curl -s http://localhost:8787/admin/tenants  # → 401
  curl -s -H "Authorization: Bearer <staging-token>" http://localhost:8787/admin/tenants  # → 200 []
  curl -s http://localhost:8787/t/foo/oidc/token  # → 503 tenant_worker_not_provisioned
  ```

- [ ] **Step 3: Open PR** on `oidc-bridge-cloud` repo.

  PR body sections:
  - **Summary** — what landed (dispatcher, registry, CFApiClient, stubs, CI)
  - **What this is _not_** — Phase 11c (tenant Worker template + canary), Phase 12c (rotation + cert upload real impl), 13c (DNS cutover), 14c (Vultr decommission)
  - **Open spec questions resolved** — Q2 path-prefix routing, Q3 bearer admin
  - **Test plan** — typecheck/lint/test/wrangler-dryrun results + curl outputs from Step 2
  - **Security** — bearer model, secrets lifecycle, no plaintext key handling in this PR (deferred to 12c)

- [ ] **Step 4: Merge** with squash, delete branch.

- [ ] **Step 5: Update `oidc-bridge` umbrella TODO row 228 (Phase 10c)** → `✅ merged (date)`, link the new PR. Mark Phase 11c (tenant Worker template + canary) as next-up.

- [ ] **Step 6: Write retro** at `oidc-bridge-cloud/docs/superpowers/retros/2026-05-XX-phase-10c-retro.md` (or `oidc-bridge` repo if the convention is to keep all retros there — decide during retro authoring; current proposal is **retro lives in the repo whose code it's about**, i.e. `oidc-bridge-cloud`).

---

## Summary

After this phase:

- A new private repo `apps-in-toss-community/oidc-bridge-cloud` exists with a green CI pipeline and a `wrangler deploy --dry-run` clean.
- The dispatcher Worker scaffold serves `/healthz`, `/.well-known/cloud-info`, bearer-auth-protected `/admin/tenants` (GET implemented; mutations stubbed), and path-prefix tenant routing with structured `503 tenant_worker_not_provisioned` for any `/t/*` traffic.
- The tenant registry D1 schema is live, with `cf_account_id NOT NULL` from day 1 (multi-account sharding ready).
- `CFApiClient` is implemented and tested against fake fetch with the documented Cloudflare API request shapes; live calls happen for the first time in Phase 12c.
- Spec §11 Q2 (tenant routing key = path prefix) and Q3 (admin auth = bearer) are resolved.
- `oidc-bridge` repo gets zero changes in this PR.

The Vultr public instance (`oidc-bridge.aitc.dev` on Node 24) keeps running. DNS unchanged. No tenant Workers exist yet. The first canary tenant deploy is Phase 11c (`aitc-sdk-example` `miniAppId=31146`).
