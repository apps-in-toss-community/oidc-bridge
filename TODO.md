# TODO

## High Priority
- [ ] Implement real Toss token verification in `POST /verify` (currently returns `501 not_implemented`). Call `/api-partner/v1/apps-in-toss/user/oauth2/generate-token`, decode the returned access-token JWT, and return normalized claims. Resolves the pre-stable gap documented in `CLAUDE.md` § Toss verification.

## Medium Priority
- [ ] M2: `POST /firebase-token` endpoint — wrap `/verify`, call `firebase-admin` `auth().createCustomToken(uid, claims)`. Returns `501 not_configured` when `FIREBASE_SERVICE_ACCOUNT` / `GOOGLE_APPLICATION_CREDENTIALS` is absent. Self-host only in v0; public instance does not hold end-user service accounts.
- [ ] M3: CORS + rate-limit + payload-cap middleware. Per-IP sliding window (default 60 req/min/IP on `/verify`-family), in-memory per instance. `X-RateLimit-*` and `Retry-After` headers. `ALLOWED_ORIGINS` env allow-list. 8 KiB payload cap. `RATE_LIMIT_ENABLED=false` default for self-host, `true` for public image.
- [ ] M4: OIDC provider surface — `GET /.well-known/openid-configuration`, `GET /.well-known/jwks.json`, `GET /authorize`, `POST /token` (standard `authorization_code` grant), `GET /userinfo`. Signing key loaded from `OIDC_SIGNING_KEY`; issuer from `OIDC_ISSUER`. JWKS derived and served.

## Low Priority
- [ ] Self-host documentation: expanded deployment recipes for Fly.io, Docker Compose, k8s, plus a sample Supabase / Auth0 / Firebase integration walkthrough.
- [ ] Observability: structured JSON logging (no PII, redacted secret keys), `x-request-id` correlation, `/healthz` with dependency checks, optional OpenTelemetry traces.
- [ ] Cloud Run deploy workflow for the public instance (M5): GitHub Actions → build + push `ghcr.io/apps-in-toss-community/oidc-bridge:{latest,sha-<sha>}` → `gcloud run deploy` to `asia-northeast3`.
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
