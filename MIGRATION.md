# Migration — M0 → zero-code mode

<!-- Verified 2026-05-12 against zero-code mode main (Phase 0–09c merged). -->

The `oidc-bridge` zero-code redesign (May 2026) is **not** backward-compatible
with the M0 `/verify` scaffold. Self-host operators of M0 must redeploy fresh.

## Cloud vs. self-host

**Using the community public instance (`oidc-bridge.aitc.dev`)?**
The public instance now runs on Cloudflare Workers, managed from the separate
[`oidc-bridge-cloud`](https://github.com/apps-in-toss-community/oidc-bridge-cloud)
repo. There is nothing to migrate or self-host — simply point your mini-app at
`https://oidc-bridge.aitc.dev/oidc/token`. The steps below are for operators
who run their own Docker-based self-hosted instance.

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

## What you need to do (self-host)

1. Take a backup of any state you care about. M0 had no persistent state;
   you can skip this if you ran the M0 image directly.
2. Pull the new image (or rebuild from source).
3. Run `oidc-bridge bootstrap` to initialize the new SQLite/Postgres
   schema and create your first user, API token, and workspace.
4. Register your mini-app(s) with `oidc-bridge app create` and upload the
   mTLS cert + key from the Apps-in-Toss console.
5. Update your mini-app to call `POST /oidc/token` (zero-code) or your
   Edge Function (confidential).

For full environment variable reference and Docker setup, see the `docker-compose.yml`
in this repo and the architecture notes in `CLAUDE.md`.
