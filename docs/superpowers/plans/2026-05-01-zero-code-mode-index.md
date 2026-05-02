# oidc-bridge zero-code mode — implementation index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each phase plan task-by-task. Steps in phase plans use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the [zero-code mode design](../specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) — a multi-tenant OIDC IdP that bridges Toss login into BaaS platforms (Supabase first), with optional confidential-client mode for Edge Function / Cloud Function operators.

**Architecture:** Hono + `@hono/node-server` on Node 24. Postgres-first storage with SQLite fallback (single-app self-host). Toss adapter via mTLS over `undici` + `https.Agent`. Sealed `ait_*` token wrapper using AES-256-GCM with HKDF-derived per-app keys. Master keys self-versioned, bytes via pluggable `MasterKeyProvider` (env / file / GCPSM lazy). RS256 id_tokens via JWKS with multi-`kid` rotation.

**Tech stack:** TypeScript ESM strict, Hono 4.x, `@hono/node-server`, `pg`, `better-sqlite3`, `bcryptjs`, `jose` (JWT/JWKS), `undici`, `pino`, `commander`, `tsdown` build, vitest, biome.

---

## Why this is split into multiple plans

The design ships in 12 phases (Phase 0–11). A single plan covering all phases is too large to author or execute as one document. Each phase is a self-contained chunk that:

- Ends green (typecheck + tests + lint clean).
- Merges to `main` before the next phase starts.
- Produces working software (or a deployable artifact, in late phases).

Each phase has its own plan file. Implementation proceeds in order; do not interleave phases.

## Phase plans

| Phase | File | Output |
|---|---|---|
| 0 | [`2026-05-01-zero-code-phase-00-skeleton.md`](./2026-05-01-zero-code-phase-00-skeleton.md) | Pino-logging Hono app, `/healthz`, build/lint/test pipelines. Removes legacy `/verify`. |
| 1 | [`2026-05-01-zero-code-phase-01-db-master-keys.md`](./2026-05-01-zero-code-phase-01-db-master-keys.md) | 7-table schema (pg + sqlite), `MasterKeyProvider`, HKDF, 6h cache. |
| 2 | [`2026-05-01-zero-code-phase-02-admin.md`](./2026-05-01-zero-code-phase-02-admin.md) | Admin REST + CLI (workspaces, apps, api_tokens), bcrypt secrets, mTLS column encryption, ownership state machine, audit log. |
| 3 | [`2026-05-01-zero-code-phase-03-oidc-token-public.md`](./2026-05-01-zero-code-phase-03-oidc-token-public.md) | `POST /oidc/token` (public client, origin auth) + JWKS + discovery, against a mocked Toss adapter. Sealed `ait_*`. |
| 4 | [`2026-05-01-zero-code-phase-04-userinfo-revoke-confidential.md`](./2026-05-01-zero-code-phase-04-userinfo-revoke-confidential.md) | `GET /oidc/userinfo`, `POST /oidc/revoke`, confidential-client auth on `/oidc/token`. |
| 5 | [`2026-05-01-zero-code-phase-05-real-toss-mtls.md`](./2026-05-01-zero-code-phase-05-real-toss-mtls.md) | Real Toss mTLS adapter, sandbox-fixture capture, error mapping, `test:e2e:live`. |
| 6 | [`2026-05-01-zero-code-phase-06-admin-sessions.md`](./2026-05-01-zero-code-phase-06-admin-sessions.md) | `user_sessions` placeholder + stub session-login endpoint behind feature flag. |
| 7 | [`2026-05-01-zero-code-phase-07-cli-bootstrap-doctor.md`](./2026-05-01-zero-code-phase-07-cli-bootstrap-doctor.md) | CLI `bootstrap` (offline) + `doctor` end-to-end. |
| 8 | [`2026-05-01-zero-code-phase-08-status-rate-limit-observability.md`](./2026-05-01-zero-code-phase-08-status-rate-limit-observability.md) | `/status` HTML page, sliding-window rate limits, pino structured logs, request-id, optional OTel. |
| 9 | [`2026-05-01-zero-code-phase-09-self-host-artifacts.md`](./2026-05-01-zero-code-phase-09-self-host-artifacts.md) | Dockerfile + docker-compose + SECURITY.md + SELF_HOSTING.md, clean-VPS smoke. |
| 10 | [`2026-05-01-zero-code-phase-10-gcp-cloud-run.md`](./2026-05-01-zero-code-phase-10-gcp-cloud-run.md) | Cloud Run service + Cloud SQL pg + GCPSM master keys + Cloud Build, DNS to `oidc-bridge.aitc.dev`. |
| 11 | [`2026-05-01-zero-code-phase-11-sdk-example-dogfooding.md`](./2026-05-01-zero-code-phase-11-sdk-example-dogfooding.md) | Replace sdk-example legacy `/verify` path with `appLogin → /oidc/token → signInWithIdToken`. M5 launch gate. |

## Universal invariants

These apply to every task in every phase. They are repeated in each phase plan's header but called out once here as the source of truth:

1. **TDD.** Every task starts with a failing test, then minimal code to make it pass, then commit. No "implement the test later" tasks.
2. **Frequent commits.** Each successful red→green cycle is a commit. Conventional Commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`.
3. **No premature abstractions.** Three duplicate lines is fine. Add a helper when there is a concrete second caller.
4. **No PII / secrets in logs.** Logger redacts known secret-named fields.
5. **Bridge never spontaneously calls Toss.** Toss is only called inside an inbound OIDC request handler.
6. **Toss `refresh_token` never leaves the sealed wrapper.** No endpoint, log, or error message exposes it.
7. **Public clients use `Origin`, never `client_secret`.** Confidential clients use `client_secret_basic` / `client_secret_post` only.
8. **mTLS material never returns from any GET.** Admin GET on `apps/:id` masks cert/key columns as `***`.
9. **Cloud-agnostic.** Any GCP-specific code path has a non-cloud alternative; GCPSM is `await import(...)`-lazy.
10. **Self-host first-class.** Every phase ends with the self-host smoke path still passing.
11. **Bite-sized tasks.** Each step is one action (≈2–5 minutes). If a step looks larger, split it.
12. **Lint + typecheck + test pass on every commit.** Pre-commit hook enforces this locally; CI enforces it on PRs.

## Working directory

All work happens in this repo. The branch `zero-code-mode` (already created from `origin/main`) is the integration branch. Each phase opens a PR to merge back into `main`.

For agentic execution, each phase plan should be executed in its own worktree. Use `gw new <phase-name> --base main` from this repo's cwd.

## Spec source of truth

If a phase plan and the spec disagree, the spec wins. Update the plan inline; do not silently diverge.

Spec: [`docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md`](../specs/2026-05-01-oidc-bridge-zero-code-mode-design.md).

## Authoring status

Phase plans are authored on demand. As of this commit, only Phase 0 is authored. Subsequent phase plans will be added as the prior phase nears completion (or in batch if the user requests the full set up front).
