# oidc-bridge zero-code mode — Phase 11c: tenant Worker template + canary deploy + Vultr cutover

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the **tenant Worker template** in the `oidc-bridge` dispatch namespace, provision the first canary tenant `aitc-sdk-example` (`miniAppId=31146`) end-to-end, run the first live `wrangler deploy --env production`, **cut DNS for `oidc-bridge.aitc.dev` from the Vultr VPS to the Cloudflare dispatcher**, verify the cloud stack is serving real traffic, then **destroy the Vultr VPS and remove the legacy GHA `deploy.yml`**. After this phase, `oidc-bridge.aitc.dev` is Cloudflare-only and `aitc-sdk-example` 31146 is ready for the M5 / 14c launch gate.

**Why fold 13c (dual-cloud cutover) and 14c (Vultr decommission) into 11c:** The Vultr public instance currently has **zero real users** (confirmed 2026-05-07 by the project owner; the instance has only ever been hit by the project's own smoke tests and the `oidc-bridge.aitc.dev` health probes). Spec §10's original plan staged a dual-cloud window for production-traffic safety; with no production traffic to protect, that staging window adds operational drag without reducing risk. Collapsing 13c+14c into 11c gives us a single, fast cutover and lets Phase 12c open against an already-Cloudflare prod stack — which is exactly the surface 12c needs (real `MtlsClient` binding, real cert rotation, real `/oidc/token` GA). Spec §10 is updated in this PR to record the merge.

**Why a separate phase from 10c:** 10c shipped the dispatcher scaffold with all admin mutations as 501 stubs and `wrangler deploy --dry-run` only. 11c is the first phase that calls real Cloudflare APIs (`POST .../mtls_certificates`, `PUT .../workers/dispatch/namespaces/.../scripts/...`), runs a real `wrangler deploy`, and touches DNS. Splitting these is a blast-radius decision: 10c could ship without an operator standing over it, 11c cannot.

**Architecture (what 11c adds):**

```
client → oidc-bridge.aitc.dev (Cloudflare DNS, post-cutover)
       → dispatcher Worker (10c, now in production)
       → env.NS.get("oidc-bridge-tenant-aitc-sdk-example").fetch()  ← NEW
       → tenant Worker (this phase)
       → 501 temporarily_unavailable for /oidc/token (12c lifts this)
       → 200 for /healthz, /.well-known/openid-configuration, /.well-known/jwks.json
```

The tenant Worker template is **runtime-agnostic Hono** that consumes the Phase 09c core (`Aead`, `Kdf`, `Random`, `Digest`, `Logger`, `MasterKeyProvider`) and serves the discoverable surface immediately. `MtlsClient` and `Storage` (per-tenant D1) bindings are wired but the `MtlsClient` is a stub that returns `501 temporarily_unavailable` — Phase 12c lands the real Cloudflare `mtls_certificates` binding that does the Toss handshake. This keeps 11c about **deployment plumbing, DNS, and decommissioning**, not about Toss-side mTLS.

Per-tenant D1 (`oidc-bridge-tenant-<tenantId>`) holds that tenant's `apps`, `user_sessions`, `audit_log` rows — the same schema as Phase 09c's D1 driver, applied per-tenant via `wrangler d1 migrations apply` at provisioning time. The shared `oidc-bridge-registry` D1 (10c) maps `tenantId → cf_account_id, worker_name, active_cf_cert_id, rotation_state`.

**Spec §11 open questions resolved this phase:**

- **Q4 — dispatcher tenant resolver caching**: resolved as **D1 read per request, no cache**. The lookup is one indexed PK read; CF Workers + D1 in the same colo measure < 5 ms. Workers KV cache is a Phase 12c+ optimization once we have measurements from real traffic. Caching now would be premature optimization with cache-coherence cost on tenant updates.
- **Q5 — cert generation latency on first registration**: resolved as **`aitcc app certs issue` from console-cli** drives Toss-side issuance. The operator runs `aitcc app certs issue --app 31146` at provisioning time; the resulting `{publicKey, privateKey}` PEMs are piped into `POST /admin/tenants/:id/cert/upload` (now real, not a 501) which forwards them to `CFApiClient.uploadMtlsCertificate` and binds the returned cert id to the tenant Worker. Onboarding UX automation (single-command `aitcc tenant onboard`) is a Phase 12c+ follow-up. Manual two-step is fine for the first canary.

**Tech stack (carried forward):** TypeScript ESM strict, Hono runtime-agnostic, `wrangler` 3.x, `drizzle-orm/d1`, `miniflare` 4 for tests, `@cloudflare/workers-types` (type-only). No `node:*` imports in `src/`. No `process.env` reads. `Buffer` forbidden. Path-prefix tenant routing (`/t/<id>/...`) confirmed from 10c — the dispatcher already does this; the tenant Worker sees the **stripped** request (`/healthz`, not `/t/<id>/healthz`). Phase 09c standing decisions and 10c standing decisions all carry forward unchanged.

---

## Universal invariants (apply to every task)

1. **No bypass of pre-commit hook.** `--no-verify` is forbidden. Hook failures get fixed at the source.
2. **TDD.** Failing test → minimal code → green → commit. Conventional Commits.
3. **No `node:*` imports in `src/`.** WebCrypto / `URL` / `TextEncoder` only. (Phase 09c standing decision.)
4. **No `process.env` reads in `src/`.** Workers `env` is the second `fetch` parameter; pass it through.
5. **`Buffer` forbidden in `src/`.** `Uint8Array` everywhere.
6. **`@cloudflare/workers-types` is type-only.** `import type { ... }`. No `/// <reference />`.
7. **`CFApiClient` stays account-aware.** Real implementations in 11c keep the `accountId` parameter; no global "the account".
8. **`cf_account_id NOT NULL` from day one** holds — in 11c the canary's row gets the real value from `wrangler.toml`'s `[env.production].vars.CF_ACCOUNT_ID`.
9. **Tenant Worker is runtime-agnostic.** Same Hono app shape that Phase 09c's `runtime/workers.ts` exercises. The tenant entry imports the runtime-abstraction core from `@ait-co/oidc-bridge-core` (or, if not yet a published package, from a `core/` git submodule or vendored path — 11c chooses the lowest-friction option; see Step 1).
10. **`POST /oidc/token` returns 501 `temporarily_unavailable` on the tenant Worker.** Same interception pattern Phase 09c established. Phase 12c removes this.
11. **DNS cutover is reversible for 24h.** Lower TTL to 60s **before** the cutover commit. Keep Vultr running until the post-cutover smoke window passes; only then destroy. (See Task 13 / Task 14.)
12. **No emojis in repo files.** Operator-facing internal tooling.
13. **Brand:** `oidc-bridge-cloud` is the **community (unofficial)** project's operator-private control plane.
14. **Lint + typecheck + test pass on every commit.** `pnpm typecheck && pnpm lint && pnpm test` is the gate. `pnpm wrangler deploy --dry-run --env production` must succeed before the live deploy.
15. **Audit-log every external-effect operation.** Every `CFApiClient` call writes a row to the `audit_log` table on the registry D1. Same shape 10c established.

## Files this phase creates / modifies

### `oidc-bridge-cloud` (operator-private)

```
oidc-bridge-cloud/
├─ src/
│  ├─ tenant-template/                 # NEW — the per-tenant Worker template
│  │  ├─ index.ts                      # NEW — tenant Worker entry (fetch handler)
│  │  ├─ app.ts                        # NEW — Hono app (discovery, JWKS, /healthz, 501 token)
│  │  ├─ env.ts                        # NEW — TenantEnv interface (DB, MASTER_KEY_*, TOSS_MTLS, …)
│  │  ├─ storage.ts                    # NEW — per-tenant D1 driver wiring (reuses 09c schema.d1.ts)
│  │  └─ mtls-client-stub.ts           # NEW — 501 stub; Phase 12c replaces with real binding
│  ├─ admin/
│  │  ├─ tenants.ts                    # MODIFIED — POST /admin/tenants now real (was 501)
│  │  ├─ rotation.ts                   # UNCHANGED — stays 501 (Phase 12c)
│  │  ├─ cert-upload.ts                # NEW — POST /admin/tenants/:id/cert/upload (real)
│  │  ├─ cf-api.ts                     # MODIFIED — putWorkerScript & uploadMtlsCertificate go live
│  │  └─ provisioning.ts               # NEW — orchestrator: create D1 → run migrations → upload cert → put script → write registry row
│  ├─ tooling/
│  │  └─ build-tenant-script.ts        # NEW — bundles tenant-template/index.ts → string for putWorkerScript
│  └─ schema.ts                        # MODIFIED — registry rows now reference real cert ids; no schema change
├─ migrations/
│  └─ 0002_tenant_indexes.sql          # NEW (if any new index needed); else no migration in this phase
├─ wrangler.toml                       # MODIFIED — [env.production] filled in (CF_ACCOUNT_ID, registry D1 id)
├─ package.json                        # MODIFIED — esbuild dep for tenant bundler; scripts: tenant:bundle, deploy:prod
├─ docs/
│  ├─ runbooks/
│  │  ├─ provision-canary-31146.md     # NEW — exact aitcc/wrangler commands for 31146
│  │  └─ vultr-decommission.md         # NEW — DNS cutover + VPS destroy steps + rollback
│  └─ superpowers/
│     └─ retros/
│        └─ 2026-05-07-phase-11c-retro.md  # NEW — written after merge
└─ test/
   ├─ tenant-template/                 # NEW — Hono app tests (discovery shape, JWKS, /healthz, 501 token)
   ├─ admin/
   │  ├─ tenants.real.test.ts          # NEW — real POST /admin/tenants flow with fake CF fetch
   │  └─ cert-upload.test.ts           # NEW — cert upload + binding flow with fake CF fetch
   └─ provisioning.test.ts             # NEW — end-to-end provisioning orchestrator with fake CF fetch + miniflare D1
```

### `oidc-bridge` (public OSS repo) — minimal changes, separate PR

```
oidc-bridge/
├─ .github/workflows/
│  └─ deploy.yml                       # DELETED — Vultr Docker deploy retired
├─ docs/
│  ├─ DEPLOY.md                        # MODIFIED — Vultr section deleted, "Cloud-hosted (oidc-bridge.aitc.dev)" pointer added
│  └─ superpowers/specs/2026-05-07-cloudflare-cloud-separation.md  # MODIFIED — §10 phase table footnote: 13c+14c merged into 11c
├─ CLAUDE.md                           # MODIFIED — Phase 11c → ✅ main row, Phase 13c/14c marked merged
├─ scripts/
│  └─ smoke/                           # MODIFIED — point smoke target at Cloudflare URL (was Vultr)
└─ TODO.md                             # umbrella sync, separate commit
```

The `oidc-bridge` PR is **strictly cleanup**: code that ran on Vultr (Dockerfile, docker-compose, ACME bootstrap, Caddy snippet) stays in git history but is removed from the working tree. Anyone who needs the self-host Docker path will rediscover it via the Phase 13c "Self-host generic Docker" milestone (now the only remaining Vultr-derived deliverable, repurposed as a generic example). Vultr-specific automation is gone for good.

---

## Tasks

Tasks are grouped: **Tenant template** (1–3) → **CF API live paths** (4–5) → **Provisioning + canary** (6–8) → **Live deploy + DNS cutover** (9–11) → **Decommission Vultr** (12–13) → **PR + retro** (14–16). Each task is a single commit. The provisioning orchestrator (Task 8) is the integration point.

### Task 1 — Bootstrap tenant-template directory + share core with `oidc-bridge`

The tenant Worker reuses the runtime-abstraction core from Phase 09c (`Aead`, `Kdf`, `Random`, `Digest`, `Logger`, `MasterKeyProvider`, `Storage` D1 driver, `runtime/workers.ts` entry). Three sharing options:

- (a) Publish `@ait-co/oidc-bridge-core` from `oidc-bridge` (npm, public scope). Cleanest, but requires a publishing pipeline.
- (b) Vendor: copy `oidc-bridge/src/core/`, `oidc-bridge/src/runtime/workers.ts`, `oidc-bridge/src/storage/schema.d1.ts`, etc. into `oidc-bridge-cloud/src/_vendor/` with a top-of-file `// SOURCE: oidc-bridge@<sha> — do not edit` header. Drift risk; lowest infra friction.
- (c) Git submodule of `oidc-bridge` at a pinned sha. Repo coupling.

**Decision for 11c: option (b) vendor** — fastest path to canary. A 12c+ task replaces it with (a) once the cert-rotation work has stabilized the surface and we know what the public package boundary really needs to be.

- [ ] Create `oidc-bridge-cloud/src/_vendor/` with `core/`, `runtime/workers.ts`, `storage/schema.d1.ts`, `storage/d1.ts`, `oidc/sealed-token.ts`, `oidc/jwks.ts`, `oidc/discovery.ts`, `master-keys/{provider,env-provider,cache}.ts`. Each file gets `// SOURCE: oidc-bridge@<sha>` at line 1.
- [ ] Add a CI check (`scripts/check-vendor-drift.ts`) that fails if the vendored sha is older than 14 days, to keep us honest.
- [ ] Test: import a vendored symbol from `tenant-template/app.ts` and assert it round-trips a sealed token (proves the vendor is loadable, not just present).

### Task 2 — Tenant Worker Hono app (read-only surface)

Mirror Phase 09c's `runtime/workers.ts` but scoped to a single tenant. The tenant id is **not** a path parameter on the tenant Worker — the dispatcher already stripped `/t/<id>/`. The tenant id is read from `env.TENANT_ID` (set per-tenant in script metadata at provisioning time).

- [ ] `src/tenant-template/app.ts`: Hono app with routes:
  - `GET /healthz` — `{ status: "ok", tenant_id: env.TENANT_ID, build_sha: env.BUILD_SHA }`
  - `GET /.well-known/openid-configuration` — `iss = env.OIDC_ISSUER + "/t/" + env.TENANT_ID`, omit `authorization_endpoint` (no OIDC redirect; Phase 09c decision)
  - `GET /.well-known/jwks.json` — JWKS from vendored `master-keys/` provider chain (env-only for now)
  - `POST /oidc/token` — **501 `temporarily_unavailable`** with `_future: { mtls_binding: "TOSS_MTLS", phase: "12c" }`
  - `GET /oidc/userinfo` — 501 same shape
  - `POST /oidc/revoke` — 501 same shape
- [ ] `src/tenant-template/env.ts`: typed `TenantEnv` — `DB: D1Database`, `MASTER_KEY_1_HEX: string`, `TENANT_ID: string`, `OIDC_ISSUER: string`, `BUILD_SHA: string`, `OIDC_ACTIVE_KID: string`, `OIDC_SIGNING_KEY_K1_PEM: string`, `TOSS_MTLS?: Fetcher` (optional; absent until 12c).
- [ ] `src/tenant-template/index.ts`: default export `{ fetch(req, env, ctx) { return app.fetch(req, env, ctx) } }`.
- [ ] Tests: discovery returns the tenant-scoped issuer; JWKS returns at least one key; `/healthz` returns 200 with the tenant id; `POST /oidc/token` returns 501 with `_future.phase === "12c"`. Use miniflare 4 to run the tenant Worker against an in-memory D1 with the schema applied.

### Task 3 — Tenant Worker bundler (script payload for `putWorkerScript`)

The CF API takes a Worker script as a string + metadata. We need an esbuild step that bundles `src/tenant-template/index.ts` into one ESM string suitable for `multipart/form-data` upload.

- [ ] Add `esbuild` dev dep.
- [ ] `src/tooling/build-tenant-script.ts`: function `buildTenantScript({ buildSha }): Promise<{ script: string; metadata: TenantScriptMetadata }>` returning the bundled ES module string and metadata (main module name, compatibility date, bindings declaration).
- [ ] `package.json` script: `"tenant:bundle": "tsx src/tooling/build-tenant-script.ts"` (writes to `dist/tenant-template.mjs` for inspection).
- [ ] Test: bundled output is non-empty, contains the JWKS handler, does not contain `node:` imports (regex assert), and is < 1 MiB (CF Worker limit is 1 MiB compressed; we want a comfortable margin).

### Task 4 — `CFApiClient.uploadMtlsCertificate` real implementation

10c's stub returned a fake id from a fake fetch. Now we hit `POST https://api.cloudflare.com/client/v4/accounts/{accountId}/mtls_certificates` for real, but tests still inject a fake fetch.

- [ ] In `src/admin/cf-api.ts`, replace the 501 body of `uploadMtlsCertificate` with a real CF API call (multipart form: `name`, `certificates` PEM, `private_key` PEM, `ca: false`).
- [ ] Map CF's response (`{ result: { id, name, ... } }`) to `{ id }`. Map error envelopes to typed `CFApiError` (status, code, message).
- [ ] Test (fake fetch): 200 success returns the id; 4xx returns `CFApiError` with `errors[0].code` exposed; PEM payload is correctly multipart-encoded.

### Task 5 — `CFApiClient.putWorkerScript` real implementation

The dispatcher uploads a tenant Worker into the `oidc-bridge` dispatch namespace. CF endpoint: `PUT https://api.cloudflare.com/client/v4/accounts/{accountId}/workers/dispatch/namespaces/{namespace}/scripts/{scriptName}`.

- [ ] In `src/admin/cf-api.ts`, replace the stub of `putWorkerScript` with a real call. Body is multipart: `metadata` JSON (compatibility date, main module, bindings: `[{ type: "d1_database", name: "DB", id }, { type: "mtls_certificate", name: "TOSS_MTLS", certificate_id }, { type: "secret_text", name: "MASTER_KEY_1_HEX" }, ...]`) + the bundled script as a module file.
- [ ] Test (fake fetch): body shape is correct (metadata JSON contains all expected bindings, script body is the bundled tenant template, content-type is `multipart/form-data`); 4xx returns `CFApiError`.
- [ ] Bindings constraint: `mtls_certificate` binding **may** be omitted in 11c (the tenant Worker tolerates `env.TOSS_MTLS === undefined` and returns 501 from `/oidc/token` regardless). The orchestrator (Task 8) wires it when the cert id is known but does not block on it.

### Task 6 — Per-tenant D1 provisioning helpers

Each tenant gets its own D1. Provisioning must: (a) create the database via CF API, (b) run the migration SQL (`oidc-bridge-cloud/migrations/tenant/0001_init.sql` — copied from `oidc-bridge`'s D1 schema), (c) record the database id in the tenant registry row.

- [ ] Add `CFApiClient.createD1Database({ accountId, name })` — `POST .../accounts/{accountId}/d1/database`.
- [ ] Add `CFApiClient.runD1Sql({ accountId, databaseId, sql })` — `POST .../accounts/{accountId}/d1/database/{id}/query`.
- [ ] `migrations/tenant/0001_init.sql` — copy from `oidc-bridge`'s `oidc-bridge/src/storage/migrations/d1/0001_init.sql` (Phase 09c output). Apply the `--` comment-strip pre-processing the 10c retro called out (helper utility shared between miniflare tests and live runs).
- [ ] Tests (fake fetch): `createD1Database` returns id; `runD1Sql` accepts statement-by-statement application; comment lines are stripped before execution.

### Task 7 — Real `POST /admin/tenants` (provisioning kickoff)

10c's stub returned 501. Now it accepts `{ tenant_id, display_name, cf_account_id?, worker_name? }` and returns `202 Accepted` with the orchestrator state.

- [ ] In `src/admin/tenants.ts`, replace the 501 body with a real handler that:
  1. Validates input shape (Zod or hand schema, consistent with 10c).
  2. Resolves `cf_account_id` (from input, falling back to `env.CF_ACCOUNT_ID`).
  3. Resolves `worker_name` as `oidc-bridge-tenant-${tenant_id}` (default).
  4. Inserts a tenant row with `rotation_state = "provisioning"`.
  5. Kicks off the orchestrator (Task 8) on the `ctx.waitUntil` queue.
  6. Returns `202` with `{ tenant_id, status: "provisioning", check_url: "/admin/tenants/:id" }`.
- [ ] If a tenant_id collision: `409 tenant_already_exists`.
- [ ] Tests (miniflare): happy path returns 202, registry row exists with `rotation_state = "provisioning"`. Collision returns 409. Bad bearer returns 401 (10c contract carries forward).

### Task 8 — Provisioning orchestrator

This is the integration point. It runs in `ctx.waitUntil` so the HTTP response returns immediately while the work continues.

- [ ] `src/admin/provisioning.ts` exports `provisionTenant({ env, registry, cfApi, tenant }): Promise<void>` that:
  1. `cfApi.createD1Database` → tenant D1 id
  2. `cfApi.runD1Sql` to apply tenant schema migration
  3. `cfApi.uploadMtlsCertificate` (skipped if no cert PEMs yet — the 11c canary calls Task 9 separately first, so the orchestrator path can be cert-less for the canary; subsequent tenants will pass cert PEMs in)
  4. `buildTenantScript` → bundled Worker script
  5. `cfApi.putWorkerScript` with bindings (D1, optional mTLS, secrets, vars)
  6. Update tenant row: `rotation_state = "active"`, `tenant_d1_id`, `cf_cert_id` (if cert was uploaded)
  7. Audit-log every CF API call with the response status and request id
- [ ] On any failure: roll the tenant row to `rotation_state = "failed"`, audit-log the failure, do **not** delete partial CF resources (operator review).
- [ ] Tests (fake fetch + miniflare D1):
  - Happy path: orchestrator runs through, all expected CF calls are made in order, registry row ends in `active`.
  - Cert-less path (canary 11c shape): orchestrator skips cert upload, ends in `active` with `cf_cert_id = null`.
  - Failure mid-orchestration (e.g. `putWorkerScript` 4xx): registry row ends in `failed`, audit log has the error, no rollback CF calls were made.

### Task 9 — Real `POST /admin/tenants/:id/cert/upload`

This is the cert-upload path that the canary uses **before** the orchestrator finishes (so the tenant Worker is born with `TOSS_MTLS` already bound). For non-canary tenants, the orchestrator's cert step (Task 8 step 3) handles it inline.

- [ ] In `src/admin/cert-upload.ts`, real implementation:
  1. Validates bearer + tenant exists.
  2. Body is multipart: `cert.pem`, `key.pem` (PEMs).
  3. Calls `cfApi.uploadMtlsCertificate({ accountId, name: "${workerName}-toss-${unix}", cert, key })`.
  4. Updates tenant row: `cf_cert_id = <new>`, `active_cert_binding = "TOSS_MTLS"`.
  5. If the tenant Worker already exists, calls `cfApi.putWorkerScript` to re-bind. (For 11c canary, the cert is uploaded **before** the Worker, so this is a no-op the first time.)
  6. Returns `200 { cf_cert_id, bound_to_worker: bool }`.
- [ ] Tests (fake fetch + miniflare): upload-before-worker returns `bound_to_worker: false`; upload-after-worker returns `bound_to_worker: true` with the re-bind call observed; bad PEM returns 400.

### Task 10 — `oidc-bridge-cloud` PR #1 (tenant template + real admin paths)

This is the substantive feature PR. Plan PR is separate; this is the implementation.

- [ ] Branch `feat/zero-code-phase-11c-tenant-template`.
- [ ] Squash all of Tasks 1–9 into one commit on the branch (or keep per-task commits; squash on merge).
- [ ] PR body: **Summary**, **Spec questions resolved (Q4 + Q5)**, **Test plan** (`pnpm test` results, `pnpm wrangler deploy --dry-run --env production` clean), **Out of scope** (live deploy + DNS in subsequent PRs of this phase).
- [ ] Merge with `gh pr merge --admin --squash --delete-branch`.

### Task 11 — Provision the canary tenant 31146 (live)

Now we exit code review and do the actual deploy. This is a runbook execution, not a PR.

- [ ] Create production registry D1: `wrangler d1 create oidc-bridge-registry-production`. Capture the id.
- [ ] Apply registry migrations: `wrangler d1 migrations apply oidc-bridge-registry-production --env production`.
- [ ] Update `wrangler.toml [env.production]`: real `CF_ACCOUNT_ID` and `database_id`. Commit + push (small PR — Task 11 ships `wrangler.toml` filled in).
- [ ] Set Workers Secrets for the dispatcher production env: `wrangler secret put ADMIN_BEARER_TOKEN --env production`, `wrangler secret put CF_API_TOKEN --env production`. Use the operator's password manager — **never** echo secrets to shell history.
- [ ] First live deploy: `wrangler deploy --env production`. Captures the dispatcher Worker bound to the production D1 + namespace.
- [ ] Smoke (Workers URL): `curl https://oidc-bridge-dispatcher.<subdomain>.workers.dev/healthz` → 200. `curl /admin/tenants -H "Authorization: Bearer $ADMIN_BEARER_TOKEN"` → 200 empty list.
- [ ] Issue cert via `aitcc app certs issue --workspace 3095 --app 31146`. Capture cert + key PEMs to a tmpfile, `0600`.
- [ ] Provision via admin API: `curl POST /admin/tenants` with `{ tenant_id: "aitc-sdk-example", display_name: "AITC SDK Example", cf_account_id: "<prod>", worker_name: "oidc-bridge-tenant-aitc-sdk-example" }` → 202.
- [ ] Upload cert via admin API: `curl POST /admin/tenants/aitc-sdk-example/cert/upload` with the PEMs → 200 with `cf_cert_id`.
- [ ] Wait for orchestrator to flip rotation_state to `active` (poll `GET /admin/tenants/aitc-sdk-example` for ≤ 60s).
- [ ] Smoke the tenant via dispatcher: `curl https://oidc-bridge-dispatcher.<subdomain>.workers.dev/t/aitc-sdk-example/healthz` → 200 with `tenant_id: "aitc-sdk-example"`. `/.well-known/openid-configuration` returns the tenant-scoped issuer.
- [ ] Capture the curl outputs into `docs/runbooks/provision-canary-31146.md` as evidence.

### Task 12 — DNS cutover `oidc-bridge.aitc.dev` → Cloudflare dispatcher

The Vultr VPS currently serves `oidc-bridge.aitc.dev`. We want the dispatcher Worker to.

**Pre-cutover (T-15min):**
- [ ] Lower the existing `oidc-bridge.aitc.dev` A record TTL to 60s on the Cloudflare DNS dashboard (or `cf-cli`). Wait one full TTL window at the previous TTL value (e.g. 5min if the old TTL was 5min).
- [ ] Confirm Vultr is still serving: `curl https://oidc-bridge.aitc.dev/healthz` → 200.

**Cutover:**
- [ ] In CF dashboard for `aitc.dev`, set up a **Worker Route** for `oidc-bridge.aitc.dev/*` that targets `oidc-bridge-dispatcher` (production env). Save.
- [ ] Wait 30s for propagation. `curl https://oidc-bridge.aitc.dev/healthz` should now return the dispatcher's health body (with the dispatcher's `service: "oidc-bridge-dispatcher"` field — distinguishable from the Vultr response that omits it).
- [ ] Verify tenant routing through the prod hostname: `curl https://oidc-bridge.aitc.dev/t/aitc-sdk-example/.well-known/openid-configuration` → 200 with `iss: "https://oidc-bridge.aitc.dev/t/aitc-sdk-example"`.
- [ ] Write the cutover timestamp into `docs/runbooks/vultr-decommission.md`.

**Soak window (T+0 → T+30min):**
- [ ] Dispatcher logs (`wrangler tail --env production`) should show the smoke traffic only; no error spikes.
- [ ] Restore TTL: bump back to 300s now that propagation is settled.

### Task 13 — Vultr VPS destroy + GHA `deploy.yml` removal

Once the soak window passes with no incidents, we permanently retire the Vultr surface.

- [ ] In a separate `oidc-bridge` repo PR (`chore/retire-vultr-deploy`):
  - Delete `.github/workflows/deploy.yml` (the SSH-into-Vultr Docker pipeline).
  - Update `docs/DEPLOY.md`: replace the Vultr SSH section with a 1-line pointer to `oidc-bridge.aitc.dev` (community public instance, now Cloudflare). Keep the self-host Docker section — that's the Phase 13c (renumbered) "Self-host generic Docker" deliverable surface, separated from production pipeline.
  - Update `scripts/smoke/` to point at `oidc-bridge.aitc.dev` (already does, but assert it's not pinned to Vultr's IP `64.176.228.95`).
  - Update `CLAUDE.md`'s milestone table: Phase 11c → ✅ main; Phase 13c (dual-cloud) merged into 11c (footnote); Phase 14c (Vultr decommission) merged into 11c (footnote).
  - Update `docs/superpowers/specs/2026-05-07-cloudflare-cloud-separation.md` §10 phase table: footnote "13c+14c collapsed into 11c (2026-05-07) — no production users, dual-cloud window not needed".
- [ ] Open the cleanup PR. CI green. Merge.
- [ ] Vultr VPS destroy via Vultr CLI or dashboard:
  - `vultr-cli instance list` → confirm the only running instance is the oidc-bridge one (instance id and IP `64.176.228.95`).
  - `vultr-cli instance delete <id>`.
  - Also delete the Vultr DNS records that pointed at `64.176.228.95` if any are managed there (the `oidc-bridge.aitc.dev` record is in Cloudflare, but double-check the operator's Vultr DNS panel).
  - Capture the destroy timestamp + screenshot in `docs/runbooks/vultr-decommission.md`.
- [ ] Workspace local cleanup (operator side, not in the PR): remove the Vultr SSH key from `~/.ssh/config` (`Host oidc-bridge-vultr` block).

### Task 14 — `oidc-bridge-cloud` PR #2 (live deploy artifacts)

`wrangler.toml` got real prod values in Task 11; the runbooks were written across Tasks 11–13. Wrap them into a documentation PR so they're reviewable.

- [ ] Branch `chore/zero-code-phase-11c-canary-runbooks`.
- [ ] Files: `wrangler.toml` (already updated), `docs/runbooks/provision-canary-31146.md`, `docs/runbooks/vultr-decommission.md`, `migrations/tenant/0001_init.sql` (if not part of PR #1).
- [ ] PR body: **Summary** of what shipped live, **Evidence** (curl outputs + Vultr destroy screenshot), **Rollback** (re-deploy Vultr from git history if needed; runbook in `vultr-decommission.md`).
- [ ] Merge with `gh pr merge --admin --squash --delete-branch`.

### Task 15 — Retro

- [ ] Write `oidc-bridge-cloud/docs/superpowers/retros/2026-05-07-phase-11c-retro.md` covering:
  - Goal vs shipped
  - Plan-vs-shipping mismatches (real CF API quirks, multipart encoding gotchas, DNS propagation timing, anything that surprised the orchestrator)
  - Spec questions resolved: Q4 (no cache for now), Q5 (aitcc-driven cert issuance)
  - Decommission notes: anything Vultr-side that surprised us
  - Standing decisions captured in CLAUDE.md (this phase): tenant template vendoring strategy, esbuild bundle for Worker upload, cert-upload-before-worker pattern for canary, post-cutover soak window discipline
  - Next phase pointer: 12c — `MtlsClient` Cloudflare binding + `/oidc/token` GA + rotation state machine
- [ ] Open as a separate PR (cosmetic), merge.

### Task 16 — Sync umbrella TODO + close the phase

- [ ] In the `apps-in-toss-community/umbrella` repo, update `TODO.md`:
  - Phase 11c row → `✅ merged (2026-05-07)`
  - Phase 13c row → `merged into 11c (2026-05-07)`
  - Phase 14c row → `merged into 11c (2026-05-07)`
  - Phase 12c row → `next-up`
  - Vultr decommission item from operations checklist → close with the destroy timestamp
- [ ] Commit + push. (No PR; TODO is push-direct on umbrella, single-author.)

---

## Acceptance signals

This phase is accepted when:

- `oidc-bridge.aitc.dev/healthz` returns the dispatcher Worker's response body.
- `oidc-bridge.aitc.dev/t/aitc-sdk-example/.well-known/openid-configuration` returns a tenant-scoped OIDC issuer document.
- `oidc-bridge.aitc.dev/t/aitc-sdk-example/.well-known/jwks.json` returns at least one signing key.
- `oidc-bridge.aitc.dev/t/aitc-sdk-example/oidc/token` returns `501 temporarily_unavailable` with `_future.phase === "12c"` (this is **expected** in 11c).
- The Vultr VPS at `64.176.228.95` is destroyed.
- The `oidc-bridge` repo `.github/workflows/deploy.yml` is deleted on `main`.
- Spec §10 phase table records the 13c+14c → 11c merge.
- Umbrella TODO closes phase 11c, 13c, 14c, and the Vultr decommission item.

After 11c, the next phase is **12c — `MtlsClient` Cloudflare binding + `/oidc/token` GA + rotation state machine**. That is when the canary's `/oidc/token` returns real tokens against Toss, and the rotation state machine in spec §5 lights up.

## Out of scope (explicitly)

- **Tenant onboarding UX automation.** The 11c canary uses two manual admin API calls (provision + cert upload). A future `aitcc tenant onboard` command consolidates this; not in 11c.
- **Hostname-based tenant routing.** Path prefix from 10c carries forward. Hostname routing (per-tenant subdomains) is a follow-up after 12c.
- **Workers KV cache for the dispatcher's tenant resolver.** D1-per-request from spec §11 Q4. Cache lands in 12c+ once measurements justify it.
- **Real `/oidc/token` flow.** Phase 12c.
- **Rotation state machine implementation.** Spec §5 work happens in 12c.
- **Self-host Docker overhaul.** Phase 13c (renumbered from the original 13c) — the only Vultr-derived deliverable that survives, generalized into a generic Docker example for self-hosters.
- **Multi-account sharding live exercise.** The plumbing is account-aware (10c standing decision); 11c uses a single CF account. Sharding lives across accounts is a follow-up before crossing 400 tenants (spec §11 Q1).

---

## Summary

After this phase:

- `oidc-bridge.aitc.dev` is served by the Cloudflare dispatcher, not Vultr.
- The first canary tenant Worker (`oidc-bridge-tenant-aitc-sdk-example`) is live in the `oidc-bridge` dispatch namespace, serving discovery + JWKS + healthz; `/oidc/token` returns 501 `temporarily_unavailable` until 12c.
- The Vultr VPS is destroyed; `oidc-bridge` repo's Vultr-specific GHA pipeline is removed; `DEPLOY.md` no longer documents Vultr.
- Spec §11 Q4 (no cache, D1 per request) and Q5 (aitcc-driven cert issuance) are resolved.
- Spec §10 phase table records that 13c (dual-cloud) and 14c (Vultr decommission) collapsed into 11c due to zero production users at cutover time.
- The cloud stack is the only stack. 12c can open against a fully Cloudflare prod surface.
