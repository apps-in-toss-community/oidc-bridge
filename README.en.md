# oidc-bridge

[한국어](./README.md) · **English**

Community-run OIDC adapter that bridges **Toss login** into BaaS platforms (Supabase, Firebase, Auth0, Keycloak, …).

## What it does

A mini-app developer registers their app with the Bridge and gets a `client_id` + an `iss = https://oidc-bridge.aitc.dev` OIDC issuer URL. The mini-app calls `appLogin()` to get a Toss `authorizationCode`; a thin consumer backend (e.g. a Supabase Edge Function) then relays it to the Bridge's `POST /oidc/token` to exchange for an OIDC `id_token`, and signs into Supabase via `signInWithIdToken`. "Zero-code" is from the **bridge-operator's perspective** — the Bridge handles all OIDC logic so the operator writes no custom code, but mini-app developers still need a thin consumer backend to relay and exchange the `authorizationCode` (clients must not call `/oidc/token` directly). For the full consumer-backend pattern and operator mTLS constraints, see the [oidc-bridge integration guide](https://docs.aitc.dev/guides/oidc-bridge).

For Edge Function / Cloud Function operators that want server authority, the same `/oidc/token` endpoint accepts `client_secret` authentication (confidential-client mode).

## Status

As of May 2026, the self-host code base for zero-code mode (Phases 0–8 and 09c) is merged to `main`, and this repo's phase plan is frozen at 09c. Subsequent cloud-side work continues in a separate private repo `oidc-bridge-cloud`. See:

- [Design spec](docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) — full architecture, components, security model.
- [Implementation index](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md) — phase-by-phase plan.
- [`MIGRATION.md`](./MIGRATION.md) — breaking change from M0.

| Phase | What landed | PR |
|---|---|---|
| 0 | Pino-logging Hono app, `/healthz`, build/lint/test pipeline. Removes legacy `/verify`. | [#19](https://github.com/apps-in-toss-community/oidc-bridge/pull/19) |
| 1 | 7-table schema (pg + sqlite), `MasterKeyProvider`, HKDF, 6h key cache. | [#19](https://github.com/apps-in-toss-community/oidc-bridge/pull/19) |
| 2 | Admin REST + CLI (workspaces, apps, api_tokens), bcrypt secrets, mTLS column encryption, ownership state machine, audit log. | [#20](https://github.com/apps-in-toss-community/oidc-bridge/pull/20), [#21](https://github.com/apps-in-toss-community/oidc-bridge/pull/21) |
| 3 | `POST /oidc/token` (public client) + JWKS + discovery, against mocked Toss. | ✅ main |
| 4–09c | userinfo + revoke, real Toss mTLS, admin sessions, CLI bootstrap, observability, runtime abstraction (Workers-ready). | ✅ main |
| 10c+ | Tenant template, DNS cutover, MtlsClient binding, `/oidc/token` GA. | oidc-bridge-cloud |

## Self-host

The public instance at `oidc-bridge.aitc.dev` is rate-limited and best-effort with no SLA; security-sensitive workloads should self-host. See [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) for a `bootstrap` + `doctor` setup walkthrough.

## License

BSD-3-Clause. See `LICENSE`.

---

Community open-source project.
