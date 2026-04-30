# TODO

## High Priority
- [ ] Cryptographic signature verification of the Toss access-token JWT. V0 decodes the AT but trusts `/oauth2/generate-token` as the verification signal (documented pre-stable gap). Unblock by confirming the JWKS URL (preferred) or shared-secret scheme with Toss, then layer `jose` verification on top of the existing decode path.

## Medium Priority
- [ ] M2: `POST /firebase-token` endpoint — wrap `/verify`, call `firebase-admin` `auth().createCustomToken(uid, claims)`. Returns `501 not_configured` when `FIREBASE_SERVICE_ACCOUNT` / `GOOGLE_APPLICATION_CREDENTIALS` is absent. Self-host only in v0; public instance does not hold end-user service accounts.
- [ ] M3: CORS + rate-limit + payload-cap middleware. Per-IP sliding window (default 60 req/min/IP on `/verify`-family), in-memory per instance. `X-RateLimit-*` and `Retry-After` headers. `ALLOWED_ORIGINS` env allow-list. 8 KiB payload cap. `RATE_LIMIT_ENABLED=false` default for self-host, `true` for public image.
- [ ] M4: OIDC provider surface — `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET /authorize`, `POST /token` (standard `authorization_code` grant), `GET /userinfo`. Signing key loaded from `OIDC_SIGNING_KEY`; issuer from `OIDC_ISSUER`. JWKS derived and served.

## Low Priority
- [ ] Self-host documentation: expanded deployment recipes for Fly.io, Docker Compose, k8s, plus a sample Supabase / Auth0 / Firebase integration walkthrough.
- [ ] Observability: structured JSON logging (no PII, redacted secret keys), `x-request-id` correlation, `/healthz` with dependency checks, optional OpenTelemetry traces.
- [x] Vultr Seoul deploy workflow for the public instance (M5): GitHub Actions → build + push `ghcr.io/apps-in-toss-community/oidc-bridge:{latest,sha-<sha>}` → scp `docker-compose.yml` + `Caddyfile` to the Vultr ICN VPS → SSH `docker compose pull && up -d` → wait for healthy. Live at <https://oidc-bridge.aitc.dev/healthz>. See [`docs/DEPLOY.md`](./docs/DEPLOY.md). _Toss partner credentials still need to be filled into `/opt/oidc-bridge/.env` on the VPS — until then `/verify` returns `500 server_misconfigured`._
- [ ] `sdk-example` auth demo wired against the public instance (M6): real toss login → Supabase/Firebase session E2E.
- [ ] Contract fixtures under `src/__fixtures__/`: redacted `/generate-token` and `/login-me` responses for unit + integration tests.
- [ ] `pnpm test:e2e:live` target — manual E2E against real Toss sandbox credentials; not in CI.

## Performance
(None)

## Backlog
- [ ] Admin-only remote MCP for ops introspection (per umbrella MCP strategy). Deferred: HTTP API + OpenTelemetry is the public surface; public MCP is a non-goal.
- [ ] Per-partner (`client_id`) rate-limit bucket — requires partner-registration UX that does not exist yet. V0 is per-IP only.
- [ ] Distributed rate-limit backend (Redis / Memorystore) for when per-instance in-memory counters become insufficient.
- [ ] OIDC signing key rotation automation for the public instance (cadence TBD; see `CLAUDE.md` open questions).
- [ ] Zero-downtime deploys via Caddy upstream pool (blue/green): two `app-blue` / `app-green` services in `docker-compose.yml`, Caddy `reverse_proxy app-blue:8080 app-green:8080 { health_uri /healthz; lb_policy first }` so it auto-fails-over. Deploy script flips the idle color, waits healthy, stops the old. No load balancer needed for single VPS. Deferred: current restart-induced 2–5s gap is acceptable at zero RPS; reconsider when first user complains or trip-style alerting goes off.
- [ ] Recurring cloud-cron ops sweep (via `/schedule`, runs on Anthropic infra, not on a laptop): monthly check of (a) GHCR image tag accumulation — prune `:sha-*` older than N, (b) Caddy / Docker minor version drift on the VPS, (c) Vultr billing sanity, (d) traffic level — open a blue/green PR if RPS crosses a threshold. Set this up once `agent-plugin` lands so the schedule's prompt can reuse umbrella-level skills, otherwise the cron prompt has to redo the cross-repo briefing each fire.
