# oidc-bridge

> Community-run OIDC adapter that bridges **Toss login** into BaaS platforms (Supabase, Firebase, Auth0, Keycloak, …).

## What it does

A mini-app developer registers their app with the Bridge and gets a `client_id` + an `iss = https://oidc-bridge.aitc.dev` OIDC issuer URL. The mini-app calls `appLogin()` to get a Toss `authorizationCode`, exchanges it at `POST /oidc/token` for an OIDC `id_token`, and signs into Supabase via `signInWithIdToken`. No backend code required (zero-code mode).

For Edge Function / Cloud Function operators that want server authority, the same `/oidc/token` endpoint accepts `client_secret` authentication (confidential-client mode).

## Status

Zero-code mode is under active implementation as of May 2026. Phases 0–2 are merged to `main`; Phase 3 (the `POST /oidc/token` endpoint) is next. See:

- [Design spec](docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) — full architecture, components, security model.
- [Implementation index](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md) — phase-by-phase plan.
- [`MIGRATION.md`](./MIGRATION.md) — breaking change from M0.

| Phase | What landed | PR |
|---|---|---|
| 0 | Pino-logging Hono app, `/healthz`, build/lint/test pipeline. Removes legacy `/verify`. | [#19](https://github.com/apps-in-toss-community/oidc-bridge/pull/19) |
| 1 | 7-table schema (pg + sqlite), `MasterKeyProvider`, HKDF, 6h key cache. | [#19](https://github.com/apps-in-toss-community/oidc-bridge/pull/19) |
| 2 | Admin REST + CLI (workspaces, apps, api_tokens), bcrypt secrets, mTLS column encryption, ownership state machine, audit log. | [#20](https://github.com/apps-in-toss-community/oidc-bridge/pull/20), [#21](https://github.com/apps-in-toss-community/oidc-bridge/pull/21) |
| 3 | `POST /oidc/token` (public client) + JWKS + discovery, against mocked Toss. | _next_ |
| 4–11 | userinfo + revoke, real Toss mTLS, admin sessions, CLI bootstrap, observability, self-host artifacts, GCP Cloud Run, sdk-example dog-fooding. | _planned_ |

## Self-host

The public instance at `oidc-bridge.aitc.dev` is rate-limited and best-effort with no SLA; security-sensitive workloads should self-host. Self-hosting docs (`SELF_HOSTING.md`) ship in Phase 9 of the implementation plan. Until then, this repo is not yet runnable as a multi-tenant production service.

## License

BSD-3-Clause. See `LICENSE`.

---

Community project. Not affiliated with Toss.
