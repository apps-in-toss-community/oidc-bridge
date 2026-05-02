# oidc-bridge zero-code mode — design spec

Status: approved (2026-05-01, brainstorming session). Successor to the M1
multi-tenant redesign ([2026-04-30 spec](./2026-04-30-oidc-bridge-m1-redesign-design.md)).
That spec is superseded — this one replaces every API surface, data model,
and module structure decision in it. Backward compatibility is **not**
preserved: the legacy `/verify` endpoint and the M1 `/oidc/*` surface defined
there are both removed. Self-host operators of M0/M1 must redeploy fresh.

## 1. North star

A mini-app developer should be able to add Toss login to a Supabase or
Firebase project **without writing or deploying any backend code** — no
Edge Function, no Cloud Function, no glue. They register their app with the
Bridge, paste their Bridge `client_id` and `oidc-bridge.aitc.dev` issuer URL
into Supabase, and call `signInWithIdToken` from the mini-app.

That is the headline path ("zero-code mode"). For operators who need server
authority — Edge Functions that authorize on behalf of users, Cloud
Functions that mint scoped credentials — a **confidential-client mode** is
available from day one, gated on the same tenant model. Both modes share
one Toss adapter, one storage layer, and one OIDC surface.

This pivots the project's center of gravity: from "OIDC + Firebase Custom
Token adapter that operators wire into their backend" to "OIDC IdP that
mini-apps can plug directly into BaaS, with confidential-client as an
opt-in extension."

## 2. Problem statement

### 2.1 What changed since the M1 spec

The M1 spec assumed every operator runs server-side code that calls the
Bridge `/oidc/token` endpoint with a `client_secret`. That assumption is
correct for some users but it forces the rest to write and operate a
function just to bridge mini-app → BaaS, even though the BaaS platform
already supports `signInWithIdToken` with a third-party OIDC IdP. Supabase
in particular treats a JWKS-publishing IdP as a first-class auth provider
and accepts an id_token signed by a JWKS-discoverable issuer with no
backend wiring.

### 2.2 What the headline mode requires

For a mini-app to call `signInWithIdToken` directly, the Bridge must:

1. **Be an OIDC IdP that publishes JWKS at a stable URL.** Supabase fetches
   `${ISSUER}/.well-known/jwks.json` to verify the id_token signature. The
   Bridge already plans this for M1.
2. **Issue an id_token signed by that JWKS, with `iss` = configured issuer
   URL and `aud` = the app's `client_id`.** Supabase rejects mismatched
   `iss`/`aud`.
3. **Accept a `POST /oidc/token` call from the mini-app itself, without a
   `client_secret`.** Mini-apps run in untrusted JS; they cannot hold a
   secret. So the app's OIDC client must be registered as **public** (no
   secret), with origin enforcement on the call.
4. **Authenticate the mini-app's `/oidc/token` call by something other than
   `client_secret`.** Origin allow-list (CORS-validated `Origin` header,
   strict equality match) plus the `authorizationCode` itself (Toss issued,
   single-use, 10 minute TTL) is the substitute. PKCE is supported but
   optional — the `authorizationCode` is already short-lived and scoped to
   the bridge issuer's verifier round-trip via mTLS.

### 2.3 What confidential-client mode requires

For an Edge Function or Cloud Function operator:

1. The same `/oidc/token` endpoint, but with `client_secret_basic` /
   `client_secret_post` authentication.
2. The response includes an `ait_access_token` — a sealed Bridge-issued
   opaque string the operator can pass back to the mini-app or use to call
   `/oidc/userinfo`.
3. The Toss `refresh_token` is **never** exposed to the operator. The
   Bridge keeps it in the sealed wrapper. To refresh, the operator calls
   `/oidc/token` with `grant_type=refresh_token` and the
   `ait_refresh_token` Bridge issued.
4. Toss's raw `accessToken` and `refreshToken` are not exposed by default.
   An admin can opt-in per app to a `/oidc/raw-tokens` endpoint that returns
   only the Toss `accessToken` (never the refresh token, never both
   together). Refresh authority stays at the Bridge.

### 2.4 What this is not

- **Not an /authorize redirect IdP.** Toss SDK does not redirect; it returns
  an `authorizationCode` from a JS call. The Bridge has no `/authorize`,
  no `response_types_supported`, no consent screen. Discovery omits both.
- **Not a Toss AT signature verifier.** Toss does not publish a partner
  JWKS. The validation signal for the Toss AT is the success of the
  subsequent mTLS `/oauth2/login-me` call. The Bridge keeps this
  property.
- **Not a generic OIDC IdP.** It bridges exactly one upstream (Toss) and
  exposes exactly the OIDC primitives BaaS platforms need to consume.

## 3. Scope

### 3.1 In scope (zero-code mode initial release)

- Single-user **API_TOKEN** admin auth, with a `users` + `api_tokens` table
  shape that allows multi-user expansion later without a schema rewrite.
- **Workspace → App** data tree. Workspace owns one or more apps; each app
  is one Toss mini-app (so `app_id` = the mini-app ID, with a user-editable
  display title). No `baas_configs` table — apps speak OIDC and BaaS
  configures itself.
- App ownership verification: α-stage auto-verify (developer mode), with a
  72-hour grace period after which an unverified app is reclaimable; lapsed
  apps are reassignable; production traffic blocked while pending.
- OIDC surface:
  - `GET /.well-known/openid-configuration` (omitting `authorization_endpoint`
    and `response_types_supported`).
  - `GET /.well-known/jwks.json` — RS256 public keys; key rotation supported
    via multiple active `kid`s.
  - `POST /oidc/token` with `grant_type=authorization_code` and
    `grant_type=refresh_token`. Both public (origin-validated) and
    confidential (`client_secret_basic` / `client_secret_post`) clients.
  - `GET /oidc/userinfo` — Bearer = sealed Bridge AT (`ait_access_token`).
    Bridge unwraps, calls Toss `/login-me` over mTLS, returns claims.
  - `POST /oidc/revoke` (RFC 7009) — accepts `ait_access_token` /
    `ait_refresh_token`. Always returns 200.
- Toss adapter (mTLS via `https.Agent` + `undici` dispatcher).
- Sealed token wrapper: AES-256-GCM with HKDF-derived per-app keys; AAD
  binds `(app_id, toss_user_key, sealing_key_version)`; key bytes live
  outside the database (env / file / cloud secret manager).
- Master-keys table — metadata only (`id`, `version`, `created_at`,
  `retired_at`, optional `provider_ref`); key bytes loaded lazily by
  provider with 6-hour TTL cache.
- Admin REST + CLI (workspaces, apps, api_tokens, raw-token toggle, master
  key rotation).
- Self-host first-class: SQLite fallback (single-app limit), filesystem
  master-key file, `docker-compose.yml`.
- Public instance on **GCP Cloud Run + Cloud SQL Postgres + Cloud Secret
  Manager** behind seven cloud-agnostic invariants (§5.6).
- sdk-example dog-fooding integration (this gates M5 launch).

### 3.2 Out of scope

- Firebase Custom Token endpoint (deferred — was M2 in old plan).
- `/authorize` redirect flow (was M4 in old plan; remains demand-driven).
- Multi-user workspaces with ACL (table shape is forward-compat; UI/CLI
  surface stays single-user for the initial release).
- Web admin console SPA (CLI is the only interface initially).
- Auto-cert renewal, mTLS client rotation automation.
- Non-Toss upstream IdPs.

## 4. Key invariants

These constraints are load-bearing. Implementation choices that violate
them must be redesigned, not patched around.

1. **Bridge is the only Toss caller.** Mini-apps and operator backends
   never speak to `apps-in-toss-api.toss.im` directly.
2. **Toss `refresh_token` never leaves the sealed wrapper.** No endpoint
   returns it; no log captures it.
3. **Refresh authority lives at the Bridge.** A sealed `ait_refresh_token`
   can only be exchanged via `POST /oidc/token`; operators cannot call Toss
   `/refresh-token` themselves.
4. **Public clients use origin enforcement, not bearer secrets.** A mini-app
   never holds a `client_secret`.
5. **mTLS material lives only in the master-key-encrypted column / secret
   manager entry.** It is never written to logs, never returned by Admin
   API GET, and is replaced (not exposed) on rotate.
6. **Master keys self-version.** The DB stores metadata; bytes load lazily
   from a `MasterKeyProvider` (env / file / GCPSM) with 6-hour TTL. Tier 3
   (HSM-backed) is a future provider, not a refactor.
7. **No spontaneous Toss calls.** Bridge calls Toss only in direct response
   to an inbound OIDC request. No background sync, no token pre-warm.
8. **Cloud-agnostic.** Every cloud-specific dependency (GCPSM, Cloud SQL
   IAM auth, Cloud Run metadata) goes behind a provider interface with at
   least one non-cloud implementation. Self-host runs the same code path.
9. **Bridge instances are stateless.** All per-request state is in the
   sealed token (`ait_*`); the database holds tenant config and the
   audit log; rate-limit counters live in a shared store, not in process
   memory. Horizontal scale-out (Cloud Run autoscaling, multi-instance
   self-host) requires no session affinity. The mini-app's next call may
   land on a different instance and unwrap the same sealed token.

## 5. Architecture

### 5.1 Data tree

```
workspace (owned by user)
└── app (one per Toss mini-app, app_id = mini-app ID)
    ├── client_secret hashes (bcrypt, multiple for rotation overlap)
    ├── mTLS cert + key (master-key-encrypted)
    ├── allowed_origins (string[])
    ├── ownership_status (pending|verified|lapsed)
    ├── ownership_grace_until (timestamp or null)
    ├── raw_tokens_enabled (bool, admin toggle, default false)
    └── display_title (user-editable)
```

There is no `baas_configs` table. Each BaaS the operator wires up reads
the standard OIDC discovery + JWKS; nothing per-BaaS is stored.

### 5.2 Module layout

```
src/
  app.ts            # Hono app factory, route mounting
  server.ts         # @hono/node-server bootstrap
  config.ts         # env parsing, default detection (cloud vs self-host)
  errors.ts         # OAuth/OIDC error envelope helpers

  oidc/
    discovery.ts    # /.well-known/openid-configuration
    jwks.ts         # /.well-known/jwks.json + key rotation
    token.ts        # POST /oidc/token (auth_code + refresh_token grants)
    userinfo.ts     # GET /oidc/userinfo
    revoke.ts       # POST /oidc/revoke
    raw-tokens.ts   # GET /oidc/raw-tokens (opt-in)
    sealed-token.ts # ait_* wrap/unwrap (AES-256-GCM + HKDF)
    id-token.ts     # JWT sign + claim mapping
    client-auth.ts  # client_secret_basic / post / public-origin

  toss/
    client.ts        # mTLS Agent factory, undici dispatcher
    generate-token.ts
    refresh-token.ts
    login-me.ts
    access-remove.ts
    envelope.ts      # SUCCESS/FAIL envelope parsing
    types.ts

  storage/
    interface.ts        # Storage abstraction (driver-agnostic surface)
    schema.pg.ts        # Drizzle pgTable definitions
    schema.sqlite.ts    # Drizzle sqliteTable mirror
    pg.ts               # Postgres driver (Drizzle + node-postgres Pool)
    sqlite.ts           # SQLite driver (Drizzle + better-sqlite3) — self-host fallback, ≤1 app
    migrate.ts          # Runtime migrate() entrypoints (drizzle-kit-generated SQL)
  drizzle/              # drizzle-kit output (committed)
    pg/                 # PG migrations + snapshot.json
    sqlite/             # SQLite migrations + snapshot.json

  master-keys/
    provider.ts      # MasterKeyProvider interface
    env-provider.ts
    file-provider.ts
    gcpsm-provider.ts # lazy-imported
    cache.ts          # 6h TTL

  apps/
    routes.ts        # Admin REST: workspaces + apps + api_tokens
    ownership.ts     # α auto-verify + 72h grace + lapsed reassign
    auth.ts          # API_TOKEN bearer + (forward) user resolution

  audit/
    log.ts           # audit_log writer

cli/
  index.ts
  commands/
    bootstrap.ts
    doctor.ts
    workspace-*.ts
    app-*.ts
    api-token-*.ts
    master-key-rotate.ts
```

### 5.3 Database schema (7 tables)

`users`, `api_tokens`, `workspaces`, `apps`, `user_sessions`, `master_keys`,
`audit_log`.

The schema is defined in TypeScript via Drizzle ORM table builders, once
per dialect (`schema.pg.ts` for `pgTable`, `schema.sqlite.ts` for
`sqliteTable`). Drizzle does not provide a cross-dialect helper; the two
files are hand-mirrored, and a storage-conformance test (§10) asserts
behavioral equivalence at runtime so the mirror cannot drift silently.
Migrations are generated per dialect by `drizzle-kit generate` and
committed under `drizzle/pg/` and `drizzle/sqlite/`.

Logical columns (cross-dialect view):

- `users` — `(id, email, created_at)`. Single user in initial release;
  schema is the multi-user-ready shape.
- `api_tokens` — `(id, user_id, name, token_hash, scopes, created_at,
  last_used_at)`. Bearer tokens for Admin REST + CLI.
- `workspaces` — `(id, owner_user_id, name, created_at)`.
- `apps` — `(id, workspace_id, app_id_toss, display_title,
  client_id, client_secret_hashes, mtls_cert_enc, mtls_key_enc,
  sealing_key_version, allowed_origins, ownership_status,
  ownership_grace_until, raw_tokens_enabled, created_at, updated_at)`.
- `user_sessions` — admin escape-hatch sessions for the future web console.
  Created in initial release as a placeholder; only API_TOKEN auth is wired.
- `master_keys` — `(id, version, created_at, retired_at, provider_ref)`.
  No key bytes.
- `audit_log` — `(id, ts, actor, action, target, details_json)`.

Dialect-specific column types (Drizzle column builders → SQL type):

| Logical type | PG (`pgTable`) | SQLite (`sqliteTable`) |
|---|---|---|
| Identifier (text PK) | `text('id').primaryKey()` (BYTEA columns excepted) | `text('id').primaryKey()` |
| Timestamp | `timestamp('ts', { withTimezone: true, mode: 'date' })` (TIMESTAMPTZ) | `integer('ts', { mode: 'timestamp_ms' })` (INTEGER ms; Drizzle returns `Date`) |
| Boolean | `boolean('flag')` | `integer('flag', { mode: 'boolean' })` |
| Bytes (mTLS material) | `bytea('mtls_cert_enc')` → `Uint8Array` | `blob('mtls_cert_enc', { mode: 'buffer' })` → `Buffer`. Drivers normalize both to `Uint8Array` at the storage interface boundary. |
| String array | `text('allowed_origins').array().notNull()` (TEXT[]) | `text('allowed_origins', { mode: 'json' }).$type<string[]>().notNull()` (TEXT, JSON-encoded) |
| JSON object | `jsonb('details_json').$type<Record<string, unknown>>()` | `text('details_json', { mode: 'json' }).$type<Record<string, unknown>>()` |
| Integer | `integer('version')` | `integer('version')` |

Postgres is the default. SQLite is supported with the constraint that
`apps` row count must be ≤ 1 (enforced at insert).

The storage interface (`storage/interface.ts`) is the contract every driver
implements. Domain types are derived from the schema via Drizzle's
`$inferSelect` so the interface, the schema, and the implementation cannot
disagree about column shape.

### 5.4 Sealed token (`ait_*`) format

```
ait_<base64url(version || iv || ciphertext || tag)>
```

- `version` — 1 byte. Identifies sealing key generation.
- `iv` — 12 bytes (GCM nonce).
- `ciphertext` — JSON-encoded `{ app_id, toss_user_key, toss_at, toss_rt,
  toss_at_exp, issued_at }`.
- `tag` — 16 bytes (GCM tag).
- AAD = `app_id || toss_user_key || sealing_key_version` (binds wrapper
  to a specific subject within a specific app generation).

Per-app sealing key = HKDF(master_key[version], salt=app.id, info="ait/seal/v1").

Tampering (any byte change, swapping app, replaying across versions) fails
GCM auth.

### 5.5 Master keys

- DB row holds metadata only. Bytes live outside DB:
  - **env** (`MASTER_KEY_<version>_HEX`) — self-host default.
  - **file** (`${MASTER_KEY_DIR}/v<version>.key`, perm 600).
  - **gcpsm** (`oidc-bridge-master-key-v<version>`) — public instance default.
- Provider chosen by `MASTER_KEY_PROVIDER` env (`env|file|gcpsm`).
- 6-hour TTL in-memory cache. On cache miss, lazy fetch.
- Rotation: admin runs `cli master-key rotate`. New version added; old
  version retained until all `apps.sealing_key_version` migrate. Rewrap
  is lazy — next time an app's tokens roll, the new version is used; an
  optional batch rewrap is provided for ops who want clean cutover.

### 5.6 Cloud-agnostic invariants (self-host first-class)

1. **Storage is an interface, mediated by Drizzle ORM.** Postgres + SQLite
   are first-class. SQL is generated by Drizzle's query builder against
   per-dialect schemas — no Cloud SQL-specific SQL, no hand-written DDL,
   no string-interpolated queries. Migrations are generated by
   `drizzle-kit` and committed under `drizzle/{pg,sqlite}/`.
2. **Master key provider is an interface.** Self-host can run with `env`
   or `file` provider; GCPSM provider is lazy-imported (`await import(...)`)
   so the package is not a hard dependency for self-host.
3. **No GCP metadata server reads in core code paths.** Cloud Run integration
   lives in deployment artifacts, not app code.
4. **Ports + addresses come from env, not platform conventions.** Bridge
   binds `0.0.0.0:${PORT||8080}`; Cloud Run respects this; docker-compose
   does too.
5. **TLS termination is external.** The bridge process does HTTP only;
   Caddy / Cloud Run / ingress handles TLS. Same code path everywhere.
6. **Logs go to stdout JSON.** Cloud Logging picks them up; self-host
   tails them with `docker compose logs`.
7. **No Cloud SQL IAM auth** in the initial release. Standard libpq
   connection string. (Cloud SQL Auth Proxy sidecar runs alongside Cloud
   Run service if used.)

### 5.7 OIDC discovery shape

```json
{
  "issuer": "https://oidc-bridge.aitc.dev",
  "jwks_uri": "https://oidc-bridge.aitc.dev/.well-known/jwks.json",
  "token_endpoint": "https://oidc-bridge.aitc.dev/oidc/token",
  "userinfo_endpoint": "https://oidc-bridge.aitc.dev/oidc/userinfo",
  "revocation_endpoint": "https://oidc-bridge.aitc.dev/oidc/revoke",
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "id_token_signing_alg_values_supported": ["RS256"],
  "subject_types_supported": ["public"],
  "scopes_supported": ["openid", "profile", "user_key"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "nbf",
    "provider", "scope",
    "toss:userKey", "toss:agreedTerms", "toss:tossAccessTokenExpiresAt"
  ],
  "code_challenge_methods_supported": ["S256"]
}
```

`authorization_endpoint` and `response_types_supported` intentionally
omitted — Toss SDK has no redirect flow.

## 6. Components

### 6.1 OIDC token endpoint

`POST /oidc/token` is the foundational endpoint. All flows funnel here.

**Public client (mini-app, zero-code mode):**
- `Origin` header must match an entry in `apps.allowed_origins` exactly.
- Body: `grant_type=authorization_code, code=<toss_authorization_code>,
  client_id=<app.client_id>, redirect_uri=<ignored>` (and optional `code_verifier`).
- Flow: lookup app by `client_id` → call Toss `/generate-token` over
  mTLS → call Toss `/login-me` over the same channel → mint id_token →
  seal `ait_access_token` + `ait_refresh_token`.
- Response:
  ```json
  {
    "access_token": "ait_...",
    "refresh_token": "ait_...",
    "id_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 3599,
    "scope": "openid profile user_key"
  }
  ```

**Confidential client (Edge Function / Cloud Function operator):**
- Same flow. Authentication is `client_secret_basic` (Authorization: Basic
  base64(client_id:client_secret)) or `client_secret_post`.
- bcrypt hash compare against any of `client_secret_hashes` (rotation
  overlap).
- Response identical to public client.

**Refresh:**
- `grant_type=refresh_token, refresh_token=ait_<...>`.
- Same auth methods (origin for public, secret for confidential).
- Bridge unwraps, calls Toss `/refresh-token`, re-seals new AT/RT.
- Toss RT never leaves the wrapper.

### 6.2 OIDC userinfo

`GET /oidc/userinfo` with `Authorization: Bearer ait_<access_token>`.

- Bridge unwraps the sealed AT, extracts `(app_id, toss_user_key, toss_at)`.
- Bridge calls Toss `/oauth2/login-me` with the Toss AT over mTLS.
- Returns the OIDC userinfo claims (same shape as id_token, plus any
  PII passthrough fields Toss returns encrypted).

The mini-app uses **the same `ait_access_token`** here that it received
from `/oidc/token`. There is no second token format and no BaaS-JWT
verification path. The mini-app holds two things post-login: the BaaS
session JWT (e.g. Supabase JWT, opaque to Bridge) and the sealed
`ait_access_token`.

### 6.3 OIDC revoke

`POST /oidc/revoke` (RFC 7009). Accepts `token` parameter (an
`ait_access_token` or `ait_refresh_token`). Always returns 200 even if
unknown / already revoked.

If the token is a refresh token, Bridge calls Toss `/access-remove` over
mTLS for the corresponding `userKey` to invalidate Toss-side state. If
access token only, Bridge marks the wrapper as revoked locally (next
unwrap fails). Local revocation list is in-memory per instance.

### 6.4 Raw tokens (opt-in)

`GET /oidc/raw-tokens` with `Authorization: Bearer ait_<access_token>`.

- 404 unless `apps.raw_tokens_enabled = true` for the requesting app.
- Returns `{ access_token: <toss_AT>, expires_in: <toss exp seconds> }`.
- **Never** returns the refresh token. Operators that want to refresh use
  `/oidc/token grant_type=refresh_token`; Bridge stays the lifecycle authority.
- Audit-logged on every call.

### 6.5 Toss adapter

- One `https.Agent` per app, lazily constructed from
  `(mtls_cert_enc, mtls_key_enc)` decrypted with the per-app sealing key.
- Wrapped by an `undici` dispatcher passed to `fetch`.
- Five operations: `generate-token`, `refresh-token`, `login-me`,
  `access-remove`, plus a thin envelope helper.
- Envelope `{ resultType: SUCCESS|FAIL, success?, error? }` is parsed in
  one place (`envelope.ts`); business code never sees the raw shape.

### 6.6 Admin REST + CLI

Endpoints (all protected by `Authorization: Bearer <api_token>`):

- `POST/GET /workspaces`, `GET /workspaces/:id`, `PATCH/DELETE /workspaces/:id`.
- `POST/GET /workspaces/:id/apps`, `GET /apps/:id`, `PATCH /apps/:id`,
  `DELETE /apps/:id`, `POST /apps/:id/secrets/rotate`,
  `POST /apps/:id/raw-tokens/toggle`, `POST /apps/:id/verify-ownership`.
- `POST/GET/DELETE /api-tokens` (scoped to the calling user).
- `POST /master-keys/rotate` (admin-only scope).

CLI is a thin wrapper over the REST API plus a `bootstrap` mode that talks
to a local SQLite DB and config file directly (no running Bridge needed
for first-time self-host setup) and a `doctor` command that validates env,
DB connectivity, master key provider, and a synthetic Toss `/login-me`
call against a sandbox cert.

### 6.7 App ownership verification

- α stage (developer mode): `POST /apps` auto-marks the app `verified`
  while the Bridge instance runs with `BRIDGE_STAGE=alpha` (env-driven,
  not per-user). Outside α, new apps are `pending` with
  `ownership_grace_until = now() + 72h`.
- During grace: token endpoint serves traffic but flags `X-Bridge-Pending: 1`
  in responses; rate-limits are tighter; production-mode mini-apps are
  blocked (referrer == DEFAULT).
- After grace expires without verification: `lapsed`. Lapsed apps are
  reassignable to other workspaces (anti-squatting).
- Verification path (post-α): the operator pastes a signed challenge into
  the Apps-in-Toss console; Bridge polls or receives a callback. Detail
  deferred to implementation.

## 7. Data flow

### 7.1 Zero-code mode (mini-app → Supabase)

```
Mini-app                Bridge                Toss (mTLS)         Supabase
   |  appLogin()           |                     |                    |
   |  → authorizationCode  |                     |                    |
   |                       |                     |                    |
   |---POST /oidc/token--->|                     |                    |
   |  grant_type=auth_code |---generate-token--->|                    |
   |  code=<authCode>      |<--------AT/RT-------|                    |
   |  client_id=<app>      |---login-me--------->|                    |
   |  Origin: <allowed>    |<------userKey-------|                    |
   |                       |                     |                    |
   |  ← id_token (RS256)   |                     |                    |
   |  ← ait_access_token   |                     |                    |
   |  ← ait_refresh_token  |                     |                    |
   |                       |                     |                    |
   |---signInWithIdToken(id_token)--------------------------------->  |
   |                       |<--JWKS fetch--------|                    |
   |                       |  /.well-known/jwks  |                    |
   |  ← supabase JWT       |                                          |
   |                       |                                          |
   |  // mini-app now holds:                                          |
   |  //   supabase JWT  (for Supabase API)                           |
   |  //   ait_access_token  (for Bridge /oidc/userinfo, /revoke)     |
```

Supabase only fetches JWKS. It never calls `/oidc/token`. The mini-app
calls `/oidc/token` itself.

### 7.2 Confidential-client mode (Edge Function operator)

```
Mini-app          Edge Function       Bridge              Toss (mTLS)
   | code  →      |                    |                    |
   |              |--POST /oidc/token->|                    |
   |              |  grant_type=auth_c |                    |
   |              |  client_secret     |--generate-token--->|
   |              |                    |<-------AT/RT-------|
   |              |                    |--login-me--------->|
   |              |                    |<------userKey------|
   |              |                    |                    |
   |              |<- ait_AT/RT, id_t  |                    |
   |              | // Edge Func uses ait_AT via /oidc/userinfo
   |              | // or hands ait_AT to mini-app
```

### 7.3 Refresh

```
Holder (mini-app or operator)    Bridge              Toss (mTLS)
       |                            |                    |
       |--POST /oidc/token--------->|                    |
       |  grant_type=refresh_token  |--refresh-token---->|
       |  refresh_token=ait_<RT>    |<------new AT/RT----|
       |                            |                    |
       |<- new ait_AT/RT, id_token  |                    |
```

## 8. Error handling

All errors use the OAuth 2.0 / OIDC envelope:
`{ "error": "...", "error_description": "..." }`.

| Condition | HTTP | error |
|---|---|---|
| Body not JSON / missing required field | 400 | `invalid_request` |
| `client_id` unknown | 401 | `invalid_client` |
| `client_secret` mismatch (confidential) | 401 | `invalid_client` |
| `Origin` not in allowlist (public) | 401 | `invalid_client` |
| `authorizationCode` rejected by Toss | 401 | `invalid_grant` |
| `refresh_token` cannot be unwrapped (tampered/expired) | 401 | `invalid_grant` |
| Toss responds FAIL on `/login-me` | 502 | `upstream_error` |
| Toss network/mTLS handshake fails | 502 | `upstream_error` |
| App not yet verified, production traffic | 403 | `app_not_verified` |
| Master key provider unavailable | 500 | `server_misconfigured` |
| DB unavailable | 500 | `server_unavailable` |
| Unexpected exception | 500 | `server_error` |

`/oidc/revoke` always returns 200 per RFC 7009, even on errors above
(except 5xx infrastructure failures).

The bridge **never** echoes upstream Toss error bodies verbatim — operators
get a sanitized `error_description` with a `request_id` for correlation.

## 9. Security model

- **mTLS material**: encrypted column + sealing-key-derived AES-GCM. Never
  in logs. Admin GET returns the column as `***`.
- **client_secret**: bcrypt(12) hashes only. Plaintext shown once at
  create / rotate time and never again.
- **API_TOKEN**: SHA-256 of `${prefix}.${random}` stored; prefix shown in
  Admin UI for identification, full token only at create.
- **id_token signing key**: RSA-2048, JWKS-published; rotation supported
  via multiple active `kid`s.
- **Sealed AT/RT**: per-app HKDF derivation; AAD binds app + subject;
  tamper-resistant.
- **Origin enforcement**: strict equality; default-deny; `ALLOWED_ORIGINS`
  env supplements per-app `allowed_origins`.
- **Rate limits**: per-IP sliding window on `/oidc/token`, per-app sliding
  window on all endpoints. Counters live in a **shared store** so multiple
  Bridge instances enforce one global limit (invariant #9). Default
  backend is Postgres (`rate_limit_counters` table, atomic increment via
  `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING`); a Redis backend
  is opt-in via `RATE_LIMIT_BACKEND=redis` for higher-throughput
  deployments. In-memory per-instance is **not** an option, even for
  self-host single-instance — the same backend code path runs everywhere
  to keep behavior identical across topologies.
- **Audit log**: every admin action, every `raw-tokens` call, every master
  key fetch. PII-free (no Toss PII, no token bodies).
- **Logging**: structured JSON; secret-key-named fields redacted at the
  logger layer.

## 10. Testing strategy

- **Unit** (vitest):
  - Sealed wrapper round-trip + tamper rejection (modify byte, swap app,
    cross-version replay).
  - id_token sign + verify against the published JWKS.
  - client-auth (basic, post, public-origin, bcrypt rotation overlap).
  - Toss envelope parsing (SUCCESS, FAIL, malformed).
  - HKDF key derivation determinism.
  - Master-key cache TTL behavior.
  - Storage interface conformance (run the same suite against pg + sqlite).

- **Integration** (Hono `app.request()` against an in-process app, no
  network):
  - `/oidc/token` happy path (public + confidential).
  - `/oidc/token` invalid_client (unknown client_id, bad secret, bad origin).
  - `/oidc/token` invalid_grant (Toss FAIL response mocked at fetch level).
  - `/oidc/userinfo` happy + bad bearer + revoked AT.
  - `/oidc/revoke` always-200.
  - Discovery + JWKS shape.
  - Admin CRUD with/without API_TOKEN.
  - App ownership grace + lapsed reassign.
  - Raw-tokens 404-when-disabled, 200-when-enabled, never-returns-RT.

- **mTLS**: indirect — assert that the `https.Agent` was constructed with
  the correct cert/key contents (intercept at `node:tls`).

- **Live e2e** (`pnpm test:e2e:live`, manual, sandbox cert required, not
  CI): full `/generate-token` + `/login-me` + `/refresh-token` round
  trip against Toss sandbox.

- **Contract fixtures**: `src/__fixtures__/` holds redacted Toss
  `/generate-token` and `/login-me` SUCCESS + FAIL responses.

- **CLI**: `--help` smoke + `bootstrap` against a temp SQLite DB +
  `doctor` golden-output snapshot.

## 11. Implementation phasing

12 phases. Each phase ends green (typecheck + tests) and merges to main
before the next starts. Phases 0–8 land before launch; phases 9–11
operationalize.

### Phase 0: Project skeleton

Scaffold-only. tsdown, vitest, biome, hono, pino. `pnpm dev`, `pnpm build`,
`pnpm test`, `pnpm lint` all green. `/healthz` returns `{status:"ok"}`.

### Phase 1: DB + master-keys foundation

Drizzle ORM schemas (`schema.pg.ts` + hand-mirrored `schema.sqlite.ts`)
covering all 7 tables. `drizzle-kit generate` produces per-dialect
migrations under `drizzle/{pg,sqlite}/`, committed. Postgres + SQLite
drivers implement the storage interface against Drizzle's query builder
(no hand-written SQL, no per-driver query duplication beyond schema
choice). Storage conformance test runs the full suite against both
drivers to catch silent schema drift. `MasterKeyProvider` interface +
env + file providers. 6h cache. Rotation API at the provider layer
(no HTTP yet). Unit tests for HKDF + cache + provider conformance.

### Phase 2: Workspaces + Apps + API_TOKEN admin

Admin REST surface: workspaces, apps (without OIDC behavior yet),
api_tokens, ownership state machine. CLI commands: `workspace`, `app`,
`api-token`. Bcrypt for client_secret hashes; column-level encryption
for mTLS material via per-app sealing key. Audit log writes.

### Phase 3: OIDC token endpoint (public client only, mock Toss)

`/oidc/token` for `grant_type=authorization_code` with origin auth and a
**mocked Toss adapter** (returns canned `/generate-token` + `/login-me`
fixtures). id_token signing + JWKS publication + discovery doc. Sealed
`ait_*` token wrap/unwrap. Refresh flow against the same mock.

### Phase 4: OIDC userinfo + revoke + confidential client

`/oidc/userinfo` (against mock Toss). `/oidc/revoke`. Confidential-client
auth (`client_secret_basic` / `client_secret_post`) on `/oidc/token`.
Origin enforcement hardening.

### Phase 5: Real Toss mTLS adapter

Replace the mock with the real adapter. Sandbox spike first: a manual
script that calls Toss sandbox with a real cert, captures responses, and
generates a fixture set. Then wire the adapter against `undici` +
`https.Agent`. Live e2e test marked `test:e2e:live`. Envelope parsing,
error mapping.

### Phase 6: Admin sessions escape hatch

Wire `user_sessions` table for the future web console (cookie-based
session for the same `users` row that owns API tokens). Initial release
exposes only API_TOKEN auth; this phase prepares the table + a stub
login endpoint behind a feature flag so the multi-user expansion does not
require a schema change.

### Phase 7: CLI + bootstrap + doctor

`bootstrap` writes a fresh SQLite DB + master-key file + first user +
first API token + first workspace. `doctor` runs env / DB / master-key /
sandbox-Toss checks. Both end-to-end against a real (sandbox) Toss cert.

### Phase 8: Status page + rate-limit + observability

`/status` HTML page (operator-facing, no auth) showing version, build
SHA, DB connectivity, master-key provider, last successful `/healthz`.
Per-IP and per-app sliding-window rate limits (in-memory). Pino structured
logs with request-id correlation. Optional OpenTelemetry export behind env.

### Phase 9: Self-hosting deployment artifacts

`Dockerfile` (multi-stage `node:24-alpine`), `docker-compose.yml`
(bridge + Postgres + Caddy), `SECURITY.md`, `SELF_HOSTING.md`. Smoke-test
the full self-host path on a clean VPS.

### Phase 10: Public-instance deployment (GCP Cloud Run)

Cloud Run service, Cloud SQL Postgres, Cloud Secret Manager for master
keys + sealing-key bytes, Cloud Build pipeline from main. DNS →
`oidc-bridge.aitc.dev`. End-to-end test from a deployed mini-app.

### Phase 11: sdk-example dog-fooding (M5 launch gate)

In `sdk-example`, replace the legacy `POST /verify` `AuthPage` with a
Supabase-only flow:
  - Mini-app calls `appLogin()`.
  - Mini-app calls `/oidc/token` against the public Bridge instance with
    `client_id` from sdk-example's registered app.
  - Mini-app calls `signInWithIdToken(id_token)` on Supabase.
  - Subsequent Supabase API calls use the resulting Supabase JWT.
  - A "show me Toss claims" button calls `/oidc/userinfo` with
    `ait_access_token`.

Successful E2E in production validates launch.

## 12. Final decision table

These are the locked decisions from the brainstorming session. They
override any text above if there is a conflict.

| # | Decision |
|---|---|
| 1 | Headline mode = zero-code (mini-app → Bridge → BaaS). |
| 2 | Confidential-client mode is in the initial release. |
| 3 | Mini-app re-auth token = sealed Bridge AT (`ait_access_token`). No second token format. No BaaS-JWT verification path on Bridge. |
| 4 | Bridge is the OIDC IdP; Toss is the upstream. No `/authorize`. |
| 5 | Discovery omits `authorization_endpoint` + `response_types_supported`. |
| 6 | id_token = RS256, JWKS-published, multiple-`kid` rotation supported. |
| 7 | Public client auth = strict-equality `Origin` header allowlist (CORS-validated). |
| 8 | Confidential client auth = `client_secret_basic` + `client_secret_post`; bcrypt(12) hash storage; rotation overlap supported. |
| 9 | PKCE supported but optional. |
| 10 | Data tree = `workspace → app`. No `baas_configs` table. |
| 11 | `app_id_toss` = Toss mini-app ID (one app row per mini-app). User-editable display title. |
| 12 | App ownership: α auto-verify + 72h grace + lapsed-reclaim. Production traffic blocked while pending. |
| 13 | Single-user admin in the initial release; `users` + `api_tokens` table shape forward-compat for multi-user. |
| 14 | (removed — no auto-matching of BaaS hooks.) |
| 15 | Toss raw tokens: opt-in `/oidc/raw-tokens` returning Toss AT only. RT never exposed. |
| 16 | Refresh = always via `/oidc/token grant_type=refresh_token`. Bridge is sole refresh authority. |
| 17 | Sealed token = AES-256-GCM + HKDF; AAD binds `app_id`, `toss_user_key`, `sealing_key_version`. |
| 18 | Master keys: self-versioned, metadata-only DB, lazy provider load, 6h TTL cache. |
| 19 | 7 tables: users, api_tokens, workspaces, apps, user_sessions, master_keys, audit_log. |
| 20 | Postgres default; SQLite fallback (≤1 app). |
| 21 | `MasterKeyProvider` providers = env, file, gcpsm. gcpsm lazy-imported. |
| 22 | Hono framework + `@hono/node-server` (chosen for portability + types, not benchmark perf). |
| 23 | Public hosting = GCP Cloud Run + Cloud SQL Postgres + Cloud Secret Manager, behind 7 cloud-agnostic invariants. |
| 24 | Self-host = same Docker image + docker-compose + filesystem master-key file. |
| 25 | Admin auth = API_TOKEN bearer; CLI + future web admin both use it. |
| 26 | Audit log records: all admin actions, raw-tokens calls, master-key fetches. PII-free. |
| 27 | (removed — no BaaS JWKS cache, since Bridge does not verify BaaS tokens.) |
| 28 | Errors use OAuth/OIDC envelope `{ error, error_description }`. |
| 29 | `/oidc/userinfo` and `/oidc/revoke` accept only sealed Bridge AT (`ait_access_token`). |
| 30 | Mini-app post-login holds two tokens: BaaS session JWT (e.g. Supabase JWT, opaque to Bridge) + sealed `ait_access_token`. |
| 31 | Storage layer = Drizzle ORM. Two hand-mirrored schema files (`schema.pg.ts`, `schema.sqlite.ts`); migrations generated by `drizzle-kit`. Storage conformance test catches drift. |
| 32 | Bridge instances are stateless (invariant #9). Sealed tokens carry all per-request state. Horizontal scale-out requires no session affinity. |
| 33 | Rate-limit counters live in a shared store (Postgres default, Redis opt-in). Same code path on self-host single-instance and Cloud Run multi-instance. |

## 13. Multi-user evolution path

The initial release ships single-user. The forward-compat mechanism:

- `users` and `api_tokens` tables exist from Phase 1. Single user is just
  one row.
- `workspaces.owner_user_id` already supports per-workspace ownership.
- Future: add `workspace_members (workspace_id, user_id, role)` table.
- API surface: `Authorization` header parses to a `(user, scopes)` tuple
  via a single `auth()` middleware. Adding session-cookie auth or OIDC-RP
  login later substitutes a different resolver, not a different surface.
- No data migration is required to flip on multi-user — only an additive
  table + a code path change.

## 14. Open questions

These are deferred, not unresolved. The initial release ships without
them; they are tracked for follow-up:

- α-stage ownership verification UX (console paste flow). The 72h
  grace + lapsed-reclaim behavior is locked; the verification *trigger*
  is implementation-detail-deferred.
- Master-key provider Tier 3 (HSM-backed). Provider interface accepts it
  with no shape change.
- Per-workspace billing / quota meters. Audit log gives the data; the
  surface is post-launch.
- Multi-region public deployment. Cloud Run supports it; we pick a single
  region (Seoul) for launch.
