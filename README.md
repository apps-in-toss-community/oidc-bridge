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
