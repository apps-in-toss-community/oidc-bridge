# PLAN — oidc-bridge

> **Scope**: this document plans the initial architecture for `@ait-co/oidc-bridge`. It is a living document during the pre-stable phase of this repo.
>
> **Status**: draft — accompanying the initial Hono scaffold PR. Many implementation details are still stubbed and marked `TODO`.
>
> **Non-official notice**: this is an unofficial, community-maintained bridge. Not affiliated with, endorsed by, or supported by Toss or the Apps in Toss team. Any observed request/response shapes in this document come from public developer-center documentation and may change without notice.

## 1. Problem statement

Toss login (via `@apps-in-toss/web-framework`'s `appLogin()`) returns a proprietary `authorizationCode`. Standard Identity-as-a-Service products (Supabase Auth, Firebase Auth, Auth0, Clerk, ...) cannot consume that directly — they expect **OIDC** or, in Firebase's case, a **Custom Token signed by a Firebase Admin service account**.

`oidc-bridge` is the thin adapter in between:

```
mini-app  ──appLogin()──▶  authorizationCode
   │
   │ POST /firebase-token { authorizationCode, referrer }
   ▼
oidc-bridge ─────▶ Toss /oauth2/generate-token ─────▶ Toss accessToken (JWT)
   │                                        │
   │                                        └─ optional: /oauth2/login-me for userKey / profile
   ▼
Firebase Custom Token (signed)  ─────▶  signInWithCustomToken() on the client
```

The same core (Toss-code-→-verified-claims) feeds an OIDC provider facade for Supabase / Auth0 style consumers.

## 2. Architectural choices

### 2.1 Framework: **Hono**

- **Runtime-agnostic** (Node, Bun, Deno, Cloud Run, Cloudflare Workers, Vercel) — matters because (a) the public instance targets Cloud Run `asia-northeast3`, and (b) self-hosters will want to drop this on whatever they already run.
- **Small surface, fast cold-start** — relevant for scale-to-zero Cloud Run.
- **First-class middleware for CORS, rate-limit, JWT verify** — all things we need.
- **`@hono/node-server`** lets us run on Node 24 (the org stack) today without locking us out of a future Workers deployment.

Fastify and Express were considered. Both are fine on Node but impose more friction on edge/runtime portability, and both lead to heavier cold starts. Hono wins on portability without losing anything we care about.

### 2.2 Storage: **none** (stateless)

- No DB, no Redis, no session store.
- Each request: Toss code in → verified claims → token out. No server-side state between requests.
- Rate-limiting state lives **in-memory per-instance** (see §5). That is adequate for the public instance's "best-effort, community-operated" promise. Self-hosters who need global rate-limiting can front with their own API gateway.

### 2.3 No MCP

See umbrella `CLAUDE.md` → MCP strategy matrix. `oidc-bridge` is plain HTTP. Admin-only remote MCP may come later for ops introspection; not part of v0.

## 3. API surface (v0)

All endpoints return JSON; errors follow RFC 7807–ish `{ error, error_description }` shape (matching OAuth 2.0 / OIDC error conventions where possible).

### 3.1 `POST /verify` — foundational

Validates a Toss `authorizationCode` and returns normalized claims. Every other endpoint (`/firebase-token`, `/oidc-token`) is built on this.

**Request**

```json
{
  "authorizationCode": "auth_xxx",
  "referrer": "DEFAULT" | "SANDBOX"
}
```

**Response 200**

```json
{
  "sub": "<stable user identifier>",
  "provider": "toss",
  "claims": {
    "userKey": "<opaque>",
    "scopes": ["user_key", "user_name", ...],
    "agreedTerms": [...]
    // any encrypted PII from /login-me stays encrypted; bridge does NOT
    // decrypt by default (see §6 "PII handling")
  },
  "tossAccessTokenExpiresAt": 1746300000
}
```

**Errors**: `400 invalid_request`, `401 invalid_code`, `502 upstream_error`, `429 rate_limited`.

### 3.2 `POST /firebase-token`

Same request as `/verify`, plus optional `{ "additionalClaims": { ... } }`.

Response `{ "customToken": "<jwt>", "uid": "<sub>", "expiresAt": ... }`.

Implementation: call internal `verify()`, then use `firebase-admin`'s `auth().createCustomToken(uid, claims)`. Service account key loaded from `GOOGLE_APPLICATION_CREDENTIALS` or `FIREBASE_SERVICE_ACCOUNT` env (JSON). See §6.

### 3.3 OIDC provider surface (deferred to follow-up PR)

Planned, not in the initial scaffold:

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /authorize` — Toss-login → redirect back with code
- `POST /token` — standard OIDC `authorization_code` grant
- `GET /userinfo`

These exist so Supabase Auth / Auth0 / Keycloak can plug the bridge in as a vanilla OIDC IdP. Signing key is a locally-held RSA/EC key, exposed via JWKS. See §6.

**Why split from `/firebase-token`**: Firebase has its own custom-token signing convention; OIDC wants a standards-compliant provider. Keeping them as separate endpoint families avoids contorting one into the other.

## 4. Toss token verification (source of truth for claims)

**All of this is based on the public developer center docs as of 2026-04.** If the docs change or we discover discrepancies in production, this section is the TODO list.

### 4.1 Flow

1. Mini-app calls `appLogin()` → gets `{ authorizationCode, referrer }` (valid 10 min).
2. Bridge receives them and calls:
   - `POST https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss/user/oauth2/generate-token`
   - Body: `{ authorizationCode, referrer }`
   - Auth: partner client credentials (`CLIENT_ID` + `CLIENT_SECRET`) — **TODO: confirm the exact auth header scheme**. Candidates: Basic auth, `X-Client-Id`/`X-Client-Secret` headers, or `client_id`/`client_secret` in body. Must be verified against docs or a working sample before we ship.
3. Response: `{ accessToken (JWT), refreshToken, tokenType: "Bearer", expiresIn: 3599, scope: "..." }`.
4. Bridge **does not forward** `refreshToken` to the caller by default. It has no use for the stateless verify path; exposing it widens blast radius.
5. (Optional, per-request flag) Bridge calls `/oauth2/login-me` with the accessToken to fetch `userKey`, `scope`, `agreedTerms`. PII fields are AES-256-GCM encrypted with a platform-issued key — see §6.

### 4.2 JWT verification (the accessToken)

The accessToken is a JWT with claims `sub`, `aud`, `scope`, `iss`, `exp`, `iat`, `jti`.

- **TODO: locate the JWKS / signing key**. Options (in order of likelihood):
  1. Toss publishes a JWKS URL — we fetch + cache.
  2. Signing is done with a shared secret tied to the partner `client_secret` (HS256). Less likely for an OAuth AT but possible.
  3. No public JWKS; we treat the AT as opaque and rely on `/login-me` round-tripping as de-facto validation.
- For v0 scaffold, the verify path **trusts the generate-token response as the sole validation signal** and decodes (but does not cryptographically verify) the AT's claims. This is explicitly flagged as a pre-stable gap and documented in the `/verify` response so downstream consumers know.
- First follow-up PR after this scaffold must close this gap.

### 4.3 Extracted claims

Mapped into the bridge's normalized response:

| Bridge claim   | Source                                     |
| -------------- | ------------------------------------------ |
| `sub`          | `userKey` from `/login-me` (stable across sessions) — **or** `sub` from the AT if `/login-me` is skipped |
| `provider`     | constant `"toss"`                          |
| `aud`          | bridge's issuer config                     |
| `claims.scopes`| AT's `scope` split                         |
| `claims.userKey` | `userKey` from `/login-me`               |
| `claims.agreedTerms` | `agreedTerms` from `/login-me`       |

PII fields (name/phone/birthday/CI/gender/nationality) are **not** placed in `claims` by default; they stay encrypted and are passed through on a per-request opt-in (`include: ["name", "phone"]`). See §6.

## 5. Rate limiting

### 5.1 Public instance

- **Strategy**: per-IP sliding-window counter, in-memory, per instance.
- **Default**: 60 requests / minute / IP to `/verify`-family endpoints; `/firebase-token` inherits same bucket (since it wraps `/verify`).
- **Per-partner (client_id) limit** is a follow-up: requires partner-registration UX we don't have yet. For v0, per-IP is the only dimension.
- **Cloud Run behavior**: scale-to-zero means counters reset when an instance spins up — this is acceptable for best-effort. When Cloud Run scales to multiple instances, counters are per-instance; effective limit is `limit × instance_count`. Documented as such.
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` on every response. `Retry-After` on 429.
- **Opt-out for self-hosters**: `RATE_LIMIT_ENABLED=false` env var (default `true` for public Docker image, `false` in dev).

### 5.2 Abuse mitigations (beyond basic RL)

- CORS allow-list configurable via `ALLOWED_ORIGINS` env (comma-separated).
- Payload size cap at 8 KiB (`/verify` + `/firebase-token`).
- Request logging: structured JSON, no PII, includes `x-request-id` correlation.
- Reject `referrer` values outside the allow-list (`DEFAULT`, `SANDBOX`).

## 6. Secrets & key handling

### 6.1 Toss partner credentials

Required by the bridge to call `/oauth2/generate-token`:

- `TOSS_CLIENT_ID`
- `TOSS_CLIENT_SECRET`
- `TOSS_API_BASE` (default `https://apps-in-toss-api.toss.im`) — overridable for sandbox.

### 6.2 Firebase service account (self-host only in v0)

- `FIREBASE_SERVICE_ACCOUNT` — raw JSON (or base64).
- `GOOGLE_APPLICATION_CREDENTIALS` — path to the JSON, as an alternative.
- Initialized lazily; `/firebase-token` returns `501 not_configured` if absent.

**Public instance does NOT hold end-user Firebase service accounts.** Each mini-app operator must self-host if they want Firebase Custom Tokens. The public instance will expose only `/verify` and the OIDC provider surface (where the bridge itself is the IdP, signed with its own key).

### 6.3 OIDC signing key (for the provider surface, follow-up)

- `OIDC_SIGNING_KEY` — PEM-encoded RSA or EC private key.
- `OIDC_ISSUER` — issuer URL that consumers will whitelist.
- JWKS is derived and served at `/.well-known/jwks.json`.
- Public instance: key rotated on a schedule, rotation events announced.

### 6.4 PII / `/login-me` decryption key

- `TOSS_PII_DECRYPTION_KEY` — optional.
- When absent: bridge returns encrypted fields untouched; caller (who legally owns the PII relationship) decrypts on their side.
- When present: bridge can decrypt selected fields if the caller passes `include: [...]`. Default-off; explicit opt-in per request.

### 6.5 Loading conventions

- All secrets via env vars. `.env` supported in dev via `dotenv/config`.
- Never logged. Structured logger redacts known secret keys by name.
- No DB-backed secrets in v0.

## 7. Deployment artifact

- **Single Docker image**, `node:24-alpine` base, multi-stage.
- Entrypoint: `node dist/server.mjs`, listens on `PORT` (default `8080` — Cloud Run convention).
- `/healthz` endpoint returns `200 ok`.
- Reproducible build: `pnpm install --frozen-lockfile` → `pnpm build`.
- Image pushed to `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>` (follow-up workflow).

## 8. Testing strategy

- **vitest** (unit): claim mapping, rate limiter, error envelope shape.
- **Integration**: spin up Hono app in-process via `app.request()` — no network. Mock the Toss upstream at the `fetch` layer.
- **Contract fixtures**: a small set of redacted `/generate-token` and `/login-me` responses committed under `src/__fixtures__/` once the scaffold is in.
- **E2E against real Toss**: only in a manual `pnpm test:e2e:live` (requires sandbox credentials). Not in CI.

## 9. Milestones

| # | Content | Status |
|---|---------|--------|
| M0 | Hono scaffold + `/verify` stub + Dockerfile + CI green | **this PR** |
| M1 | Real `/verify` implementation against Toss generate-token, with JWT sig verification resolved | next |
| M2 | `/firebase-token` + Firebase Admin integration (self-host) | next |
| M3 | Rate-limit middleware + CORS + payload caps | next |
| M4 | OIDC provider surface (`/authorize`, `/token`, JWKS) | follow-on |
| M5 | Cloud Run deploy workflow for the public instance | follow-on |
| M6 | `sdk-example` auth demo wired against the public instance | after M4 |

## 10. Open questions (tracked as TODO in code)

1. Exact auth scheme for Toss partner API (`generate-token` request auth) — see §4.1.
2. AT signature verification path (JWKS? shared secret? opaque?) — see §4.2.
3. Whether `/login-me` is mandatory on every verify or opt-in — current plan is opt-in, but `sub` stability may force mandatory.
4. OIDC signing key rotation cadence for the public instance (every 90 days? configurable?).
5. Whether to provide per-partner rate buckets pre-registration (likely "no" for v0).
