# oidc-bridge M1 redesign — design spec

Status: approved (2026-04-30, brainstorming session). Successor to the
previous M1 framing (single-`/verify` endpoint with deferred AT signature
verification). This spec replaces that direction.

## 1. North star

Apps-in-Toss mini-app developers should be able to add Toss login to a
Supabase or Firebase backend with the same effort they would spend wiring up
"login with Google" — without ever having to set up mTLS themselves and
without writing more than ~10 lines of glue code in their function/edge
runtime.

The bridge is the OIDC + Custom Token adapter that makes this possible.
It terminates mTLS toward Toss, hides the proprietary `/oauth2/...` partner
shape behind a standard OIDC surface, and (for self-host operators only)
issues Firebase Custom Tokens directly so Spark-plan users — who cannot make
outbound calls from Cloud Functions — still have a path.

## 2. Problem statement

### 2.1 Toss is not an OIDC IdP

Toss provides a JS SDK function (`appLogin()`) that returns
`{ authorizationCode, referrer }` and a partner HTTP API at
`https://apps-in-toss-api.toss.im` exposing five endpoints under
`/api-partner/v1/apps-in-toss/user/oauth2/...`. None of the OIDC primitives
exist: no `/authorize`, no JWKS, no `state` or PKCE handling, no standard
discovery document. The access token Toss returns is a JWT
(`alg=RS256, kid="cert", iss="https://cert.toss.im"`) but Toss does not
publish a JWKS endpoint, so partners cannot verify it locally; the documented
validation signal is the success of `/oauth2/login-me` itself.

### 2.2 Toss partner API requires mTLS

The partner API authenticates clients via mTLS using a cert+key pair issued
in the Apps-in-Toss console (390-day validity, multiple per app, single
cert covers both `DEFAULT` and `SANDBOX` referrers). It does not document
HTTP Basic Auth or any header-based credential — the existing scaffold's
Basic Auth assumption is wrong and must be replaced.

Outbound mTLS is awkward in the runtimes our target users operate in:
- **Supabase Edge Functions** (Deno Deploy): client-cert support in the
  edge runtime is restricted; setting up mTLS per request is not ergonomic
  and not portable across edge regions.
- **Firebase Cloud Functions**: gen2 runtime supports outbound mTLS via
  `https.Agent` and Secret Manager but onboarding friction is high.
- **Firebase Functions on Spark**: Spark explicitly blocks all outbound
  network requests except to Google services. **No path to call Toss
  directly exists for Spark users at all.**

### 2.3 Result: bridge is the integration path, not just an adapter

The bridge is not optional convenience — without it, Supabase Edge and
Firebase Spark users have no realistic way to integrate Toss login. The
public bridge instance must therefore be operated as a real product (Vultr
Seoul VPS + Cloudflare → `oidc-bridge.aitc.dev`, per umbrella domain
policy), and the self-host path must remain first-class so security-sensitive
operators can run their own.

## 3. Scope

### 3.1 In scope (M1)

- Multi-tenant tenant model. Tenant = (mTLS cert + key, OIDC client_id,
  OIDC client_secret, optional metadata).
- Tenant store with two backends:
  - filesystem (self-host default)
  - Google Secret Manager (public instance default, asia-northeast3)
- Admin REST API for tenant CRUD: `POST/GET/PATCH/DELETE /admin/tenants`,
  `POST /admin/tenants/:id/secrets/rotate`. Bearer-token-protected with a
  static admin token (`ADMIN_TOKEN` env). Future console SPA layers on top.
- Bundled CLI as a thin REST client over the Admin API. Same set of
  operations. Supports a "self-host bootstrap" mode where the CLI talks to
  a local config file directly (no Bridge process required for first-time
  setup).
- OIDC surface:
  - `GET /.well-known/openid-configuration` — discovery document. Lists
    `issuer`, `jwks_uri`, `token_endpoint`, `userinfo_endpoint`,
    `revocation_endpoint`, supported algorithms, supported scopes, supported
    grant types (`authorization_code`, `refresh_token`). Does **not** list
    `authorization_endpoint` because Toss does not support OIDC redirect.
  - `GET /.well-known/jwks.json` — public keys for verifying ID tokens.
    Single signing key for v1; rotation primitives in place but not
    automated in M1.
  - `POST /oidc/token` — `grant_type=authorization_code` (code = Toss
    authorizationCode) and `grant_type=refresh_token` (refresh_token = our
    sealed wrapper around the Toss refreshToken). Authenticates the client
    with `client_secret_basic` or `client_secret_post`. Returns standard
    `{ access_token, id_token, refresh_token, token_type, expires_in,
    scope }`. Internally calls Toss `/generate-token` (or `/refresh-token`)
    over mTLS using the tenant's cert.
  - `GET /oidc/userinfo` — Bearer-authenticated. Unwraps the sealed
    `access_token`, calls Toss `/login-me` over mTLS, returns claims. PII
    fields are passed through in their Toss-encrypted form (passthrough
    only).
  - `POST /oidc/revoke` — RFC 7009. Maps to Toss
    `/access/remove-by-access-token`. (`/access/remove-by-user-key` is not
    used in M1 — the bridge always has the AT to hand because revoke is
    Bearer-authenticated with our sealed access_token.)
- Toss adapter (`src/toss/`):
  - mTLS client (`https.Agent` with PEM cert+key from tenant store).
  - Response envelope handling — Toss responses are
    `{ resultType: "SUCCESS"|"FAIL", success?: {...}, error?: {...} }`,
    not the flat shape the current scaffold assumes. The adapter is the
    sole place that knows about this envelope.
  - Claim mapping table:
    | OIDC claim | Source |
    |---|---|
    | `sub` | `userKey` from `/login-me` (string-cast) |
    | `iss` | bridge issuer URL (env `OIDC_ISSUER`) |
    | `aud` | OIDC `client_id` (= tenant_id) |
    | `iat`, `exp`, `nbf` | bridge clock (id_token TTL = 1 hour, matching Toss AT) |
    | `provider` | constant `"toss"` |
    | `scope` | Toss-returned scope, space-joined |
    | `toss:userKey` | numeric `userKey` (preserved type) |
    | `toss:agreedTerms` | array of strings from `/login-me` |
    | `toss:tossAccessTokenExpiresAt` | unix seconds |
- Sealed-wrapper access tokens. Bridge `access_token` is an opaque string
  that wraps `(tenant_id, toss_access_token, toss_refresh_token, exp)`
  encrypted with a per-tenant sealing key. Bridge has no separate session
  store. Format: `aitc_<base64url(AEAD ciphertext)>`. AEAD = AES-256-GCM.
  Sealing key derived per-tenant from the master key + tenant_id (HKDF).

### 3.2 In scope (M2 — self-host Firebase Spark path)

- `POST /firebase-token` — self-host-only endpoint. Accepts a Toss
  authorizationCode (or a bridge access_token), runs the same Toss adapter
  flow, and signs a Firebase Custom Token using `firebase-admin`. Service
  account loaded from `FIREBASE_SERVICE_ACCOUNT` (raw JSON or base64) or
  `GOOGLE_APPLICATION_CREDENTIALS`. Returns `501 not_configured` when no
  service account is available; the public instance is therefore a no-op
  here by design.
- Self-host docs: full Cloud Run free-tier deployment guide so a Spark
  user can run their own bridge for $0 and call `/firebase-token` directly
  from the mini-app.

### 3.3 In scope (M5 — public-instance launch + sdk-example dog-fooding)

The public instance does not "go live" until the bridge has at least one
real consumer end-to-end. That consumer is **`sdk-example` itself**: we
register it as the founding tenant on the public instance and rebuild
its `AuthPage` to sign a real user into Supabase via our `/oidc/token`.
This is the primary quality gate for M1 — if the team that built the
bridge can't wire up Supabase + Toss login through it in a single
afternoon, no external operator will either.

- Cloud Run deploy workflow + DNS to `oidc-bridge.aitc.dev` + first
  tenant provisioned via the bundled CLI against the public instance.
- `sdk-example` switches its `AuthPage`'s OIDC bridge demo from the
  legacy `POST /verify` shape to a Supabase Edge Function
  (`supabase/functions/toss-login`) that calls `POST /oidc/token` with
  `client_secret_basic` and returns the `id_token` to the SPA, which then
  calls `supabase.auth.signInWithIdToken({ provider, token })`.
- The Edge Function source becomes the canonical "Supabase + Toss login"
  reference snippet for the bridge README and for `agent-plugin`'s
  `/ait new` template.
- sdk-example's hosting moves from GitHub Pages to a host with serverless
  functions (Cloudflare Pages or Vercel) so the Edge Function can run
  alongside the SPA. Static SPA build remains identical.
- A small "demo data" RLS policy in Supabase auto-deletes user rows after
  14 days; no PII columns. README documents that the demo Supabase
  project is not a production trust boundary.

### 3.4 Out of scope (deferred)

- `/oidc/authorize` redirect flow. Toss SDK does not support `redirect_uri`
  or `state`, so a fully-automated OIDC-consumer redirect path is not
  available without a hosted helper mini-app. Revisit when product demand
  warrants the operational cost of registering a community mini-app in the
  Apps-in-Toss console.
- Rate limit, CORS allow-list, payload cap (M3 in the existing CLAUDE.md
  milestone table).
- JWE-encrypted PII or partner-side decryption (M4-ish). PII stays as Toss-
  encrypted opaque strings on the wire; downstream consumers decrypt at
  their own boundary using their own Toss-issued PII key.
- Toss accessToken signature verification. Toss does not publish JWKS and
  does not document partner-side signature verification; it documents
  `/login-me` success as the canonical validation signal. The bridge treats
  the AT as opaque and never grants authority based on its claims directly
  — every claim that flows out comes from `/login-me` (whose response is
  authenticated by the mTLS channel + bearer token combination). The
  pre-stable-gap framing in `CLAUDE.md` is therefore deleted, not closed.
- Public instance admin console SPA (separate repo when needed).
- Distributed tenant store / Redis-backed sealing-key cache.
- `/firebase-token` on the public instance (security: we will not custody
  end-user Firebase service accounts).

## 4. User experience

### 4.1 Tenant onboarding

1. Operator registers their mini-app in the Apps-in-Toss console.
2. Operator goes to console → mTLS 인증서 → +발급받기 → downloads
   `client-cert.pem` and `client-key.pem`.
3. Operator runs `oidc-bridge tenant create --cert client-cert.pem
   --key client-key.pem --name "<friendly name>"` (against the public
   instance via `--bridge https://oidc-bridge.aitc.dev` or against a
   local self-host).
4. CLI prints `client_id` and `client_secret`. Secret is shown once; the
   bridge stores only a hash and cannot recover it.
5. Operator pastes `client_id`/`client_secret` into Supabase / Auth0 /
   Keycloak / Firebase Identity Platform / their own Cloud Function
   secrets.

### 4.2 Per-runtime user code

#### Supabase Edge Function

This snippet is the canonical Supabase reference and lives at
`sdk-example/supabase/functions/toss-login/index.ts` once M5 lands. It
runs unchanged on Deno Deploy; the bridge does not require any
Supabase-specific shim.

```ts
// edge function: toss-login
Deno.serve(async (req) => {
  const { authorizationCode } = await req.json();
  const r = await fetch("https://oidc-bridge.aitc.dev/oidc/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: authorizationCode,
      client_id: Deno.env.get("OIDC_BRIDGE_CLIENT_ID")!,
      client_secret: Deno.env.get("OIDC_BRIDGE_CLIENT_SECRET")!,
    }),
  });
  const { id_token } = await r.json();
  return new Response(JSON.stringify({ id_token }));
});
```

The SPA then calls `supabase.auth.signInWithIdToken({ provider: "oidc",
token: id_token })`. `client_secret` lives only in the Edge Function's
environment; it is never shipped to the browser.

#### Firebase Blaze + Identity Platform

Same pattern in a Cloud Function — Identity Platform validates the ID token
against our `jwks_uri`. User code is ~10 lines.

#### Firebase Spark (self-host only)

Operator runs the bridge on Cloud Run free tier (or any Docker host) with
their Firebase service account injected. Mini-app calls `/firebase-token`
directly:

```ts
const { authorizationCode } = await appLogin();
const r = await fetch("https://my-bridge.example.com/firebase-token", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ authorizationCode, client_id, client_secret }),
});
const { custom_token } = await r.json();
await firebase.auth().signInWithCustomToken(custom_token);
```

Public instance returns `501 not_configured` for `/firebase-token` — Spark
users are expected to self-host. README documents this clearly.

#### Auth0 / Keycloak / generic OIDC

Console-only registration with our discovery URL. Zero code beyond the
existing OIDC integration the operator already has.

## 5. Architecture

### 5.1 Module layout

```
src/
  app.ts                     // Hono app factory, route mounting
  server.ts                  // entrypoint
  oidc/
    discovery.ts             // /.well-known/openid-configuration
    jwks.ts                  // /.well-known/jwks.json
    token.ts                 // POST /oidc/token
    userinfo.ts              // GET /oidc/userinfo
    revoke.ts                // POST /oidc/revoke
    sealed-token.ts          // AEAD wrap/unwrap for our access_token
    id-token.ts              // ID token sign/verify (jose)
    client-auth.ts           // client_secret_basic + client_secret_post
  toss/
    client.ts                // mTLS https.Agent + fetch wrapper
    generate-token.ts
    refresh-token.ts
    login-me.ts
    access-remove.ts
    envelope.ts              // resultType envelope handling
    types.ts
  tenants/
    store.ts                 // TenantStore interface
    fs-store.ts              // filesystem backend
    gcpsm-store.ts           // Google Secret Manager backend
    types.ts                 // Tenant, TenantSecrets
  admin/
    routes.ts                // /admin/tenants CRUD
    auth.ts                  // ADMIN_TOKEN bearer middleware
  firebase/                  // (M2)
    custom-token.ts
    routes.ts
  config.ts                  // env parsing, runtime mode (public/self-host)
  errors.ts                  // OAuth2/OIDC error envelope
cli/
  index.ts                   // commander or citty
  commands/
    tenant-create.ts
    tenant-list.ts
    tenant-show.ts
    tenant-rotate-secret.ts
    tenant-delete.ts
```

Files stay focused: each route module owns one endpoint plus its small
input parsing. Shared concerns (sealed token, ID token signing, client
auth, errors) live in their own files.

### 5.2 Tenant store interface

```ts
interface TenantStore {
  get(tenantId: string): Promise<Tenant | null>;
  getByClientId(clientId: string): Promise<Tenant | null>;
  list(): Promise<TenantPublic[]>;       // no secrets
  create(input: TenantCreateInput): Promise<{ tenant: Tenant; clientSecret: string }>;
  rotateSecret(tenantId: string): Promise<{ clientSecret: string }>;
  delete(tenantId: string): Promise<void>;
}

interface Tenant {
  id: string;                            // tnt_<24 base32>
  name: string;
  clientId: string;                      // = id, exposed as `client_id`
  clientSecretHashes: { hash: string; createdAt: number }[];  // bcrypt; array supports rotation overlap
  mtlsCert: string;                      // PEM, encrypted at rest in GCPSM
  mtlsKey: string;                       // PEM, encrypted at rest in GCPSM
  mtlsExpiresAt: number;                 // parsed from cert NotAfter
  sealingKeyVersion: number;             // for AEAD key derivation
  createdAt: number;
  updatedAt: number;
}
```

`fs-store` writes one JSON file per tenant under `${BRIDGE_DATA_DIR}/tenants/${id}.json`.
`gcpsm-store` stores the JSON blob as a Secret Manager secret named
`oidc-bridge-tenant-${id}` and indexes by `clientId` via a labels query
(or a small `clientId → id` mapping secret).

The master sealing key is in a separate secret (`oidc-bridge-master-key`)
and never leaves the process memory once loaded.

### 5.3 OIDC `/token` flow (authorization_code)

1. Parse client_id from header (Basic) or body. Look up tenant. Verify
   client_secret against any of `clientSecretHashes` (overlap support).
2. Parse `code` (= Toss authorizationCode) and `referrer` body field
   (default `DEFAULT`; `SANDBOX` for non-production tests).
3. Load tenant mTLS cert+key, build `https.Agent`.
4. POST to Toss `/generate-token` over mTLS with body
   `{ authorizationCode, referrer }`. Parse envelope.
5. On success: call Toss `/login-me` over mTLS (HTTP method per Toss API
   spec) using the just-issued accessToken as bearer. Parse envelope.
   Read `userKey` (number), `scope`, `agreedTerms`, encrypted PII fields.
6. Build claims (table in §3.1). Sign ID token with bridge signing key
   (RS256, jose).
7. Wrap `(tenant_id, toss_access_token, toss_refresh_token, exp)` into
   sealed bridge `access_token`. Same for refresh_token (longer TTL,
   Toss RT = 14 days).
8. Return standard OAuth2 response.

Failure paths: Toss 4xx → `invalid_grant`; envelope `FAIL` →
`invalid_grant` with `error_description` from Toss `reason`; mTLS handshake
failure → `temporarily_unavailable` (502). Misconfiguration (no tenant
found, expired cert) → `invalid_client` (401).

### 5.4 OIDC `/userinfo` flow

1. Parse `Authorization: Bearer aitc_...`.
2. Unwrap sealed access_token. Verify AEAD tag. Extract tenant_id.
3. Load tenant mTLS cert+key.
4. Call Toss `/login-me` (per Toss API spec) with the embedded
   toss_access_token. Parse envelope.
5. Return claims as JSON. PII fields stay base64-or-encrypted as Toss
   returns them; consumer decrypts on their side.

### 5.5 OIDC `/revoke` flow

1. Bearer auth (same unwrap).
2. POST Toss `/access/remove-by-access-token` over mTLS.
3. RFC 7009 says always return 200, even on failure — comply.

### 5.6 Discovery document

```json
{
  "issuer": "https://oidc-bridge.aitc.dev",
  "jwks_uri": "https://oidc-bridge.aitc.dev/.well-known/jwks.json",
  "token_endpoint": "https://oidc-bridge.aitc.dev/oidc/token",
  "userinfo_endpoint": "https://oidc-bridge.aitc.dev/oidc/userinfo",
  "revocation_endpoint": "https://oidc-bridge.aitc.dev/oidc/revoke",
  "id_token_signing_alg_values_supported": ["RS256"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["openid", "profile", "user_key", "user_name", "user_phone", "user_birthday", "user_gender", "user_nationality", "user_ci"],
  "subject_types_supported": ["public"],
  "claims_supported": ["sub", "iss", "aud", "iat", "exp", "nbf", "provider", "scope", "toss:userKey", "toss:agreedTerms", "toss:tossAccessTokenExpiresAt"]
}
```

`authorization_endpoint` and `response_types_supported` are intentionally
omitted — Toss SDK does not support OIDC redirect, so there is no browser
flow to advertise. Consumers MUST use server-to-server `/oidc/token`
followed by `signInWithIdToken` (Supabase / Firebase Identity Platform) or
equivalent. README documents this prominently.

## 6. Security model

- **Tenant secrets at rest**: GCPSM (public) or filesystem with permission
  600 (self-host). Never logged.
- **client_secret**: bcrypt hash only. Plaintext shown once at creation
  and rotation. Hash list (not single value) supports zero-downtime
  rotation.
- **Sealing key**: per-tenant key derived via HKDF from a process-wide
  master key + tenant_id. Master key in env (`OIDC_MASTER_KEY`,
  base64 32 bytes) for self-host or in GCPSM (`oidc-bridge-master-key`)
  for public. Rotation requires re-issuing all tokens — accepted, opaque
  tokens have <= 14-day lifetime so rotation drains within RT TTL.
- **ID token signing key**: separate from sealing key. RS256 RSA-2048
  generated per deployment, public half exposed via `/jwks.json`. Rotation
  not automated in M1; manual cycle with overlap by adding a new key to
  JWKS, signing with new, then dropping old after RT TTL.
- **mTLS expiry monitoring**: Bridge surfaces `mtlsExpiresAt` on
  `GET /admin/tenants/:id`. CLI `tenant list` warns at <30 days. Public
  instance emails operator at -30, -7, -1 days (M5; M1 just exposes the
  field).
- **PII**: never decrypted. The bridge has no PII decryption key in
  scope. Documented as a property of the system, not a future feature.
- **Admin auth**: static bearer token (`ADMIN_TOKEN` env). For public
  instance pre-console, treat as a single-operator secret. Console SPA
  layers per-user OAuth on top later.
- **Rate limiting**: out of M1 scope (M3) but Cloud Run / Vultr layer can
  drop early if needed.

## 7. Dependencies (new)

- `jose` — ID token sign/verify, JWKS encoding.
- `bcryptjs` — client_secret hashing. (`bcrypt` native is fine too; pick
  the smaller dep at implementation time.)
- `@google-cloud/secret-manager` — GCPSM backend (lazy-imported, only
  loaded when `TENANT_STORE=gcpsm`).
- `firebase-admin` — M2 only. Lazy-imported.
- `commander` (or `citty`) — CLI.
- `node:crypto` — AES-256-GCM, HKDF (built-in).
- `node:tls` / `https.Agent` — mTLS (built-in).

## 8. Testing strategy

- **Unit tests** (`vitest`):
  - Sealing wrap/unwrap roundtrip + tamper rejection.
  - ID token sign/verify against an in-test JWKS.
  - Client auth (Basic + Post + bcrypt rotation overlap).
  - Toss envelope parsing (success + FAIL).
  - Claim mapping pure-function table tests.
- **Integration tests** (Hono `app.request()`, no network):
  - `/oidc/token` happy path with mocked Toss `fetch`. Asserts mTLS Agent
    presence on the outgoing call and standard token response shape.
  - `/oidc/token` invalid_client / invalid_grant paths.
  - `/oidc/userinfo` happy path + bad bearer.
  - `/oidc/revoke` always-200 contract.
  - Discovery + JWKS shape against `id_token_signing_alg_values_supported`
    consistency.
  - Admin CRUD paths under admin token + reject without.
- **Contract fixtures** under `src/__fixtures__/` — redacted Toss
  `/generate-token` and `/login-me` responses, both `SUCCESS` and `FAIL`
  envelopes.
- **CLI**: `--help` smoke + create-then-list against an in-process Bridge
  (Hono serve on ephemeral port).
- **mTLS**: covered indirectly by asserting our `https.Agent` is built
  with the tenant's PEM bytes. End-to-end mTLS handshake against a real
  Toss host is left to a manual `pnpm test:e2e:live` target (sandbox
  credentials required, not in CI).

## 9. Rollout

The bridge is a Type C service repo (no semver contract, no published
consumers yet). M1 ships as a single breaking change rather than a
flagged migration:

- `/verify` is removed. Self-host operators get `MIGRATION.md` covering
  the move from `TOSS_CLIENT_ID/SECRET` env vars to CLI-driven tenant
  create + `/oidc/token`. The old envs are dropped in the same release.
- Public instance (`oidc-bridge.aitc.dev`) goes live only after **all**
  of the following pass (M5 launch gate):
  1. `/admin/tenants` is gated behind `ADMIN_TOKEN`.
  2. Master sealing key is provisioned in GCPSM.
  3. CLI ships a working `tenant create` against the deployed instance.
  4. **sdk-example dog-fooding succeeds end-to-end**: a real `appLogin()`
     in sdk-example completes a Supabase `signInWithIdToken` round-trip
     via the public bridge, with the `id_token` validated by Supabase
     against our published JWKS. If this fails, the bridge isn't ready —
     no external operator will have a smoother time than we do.
- Cloud Run revision is rolled with `--no-traffic` first, smoke-tested
  via the CLI, then promoted to 100%. Roll-back is a `gcloud run
  services update-traffic` to the prior revision; tenant data lives in
  GCPSM independent of the revision.

## 10. Open questions

- **Refresh token Toss-side rotation**: Toss `/refresh-token` may or may
  not rotate the RT (docs do not say). Implementation must observe both
  cases: if Toss returns a new RT, our sealed bridge RT updates; if not,
  we re-wrap the existing RT with a new exp. To be confirmed in
  integration testing.
- **`referrer` parameter routing**: the Toss `/generate-token` body needs
  a `referrer` (`DEFAULT` | `SANDBOX`). OIDC `/token` does not have a
  natural place for it. Decision: read from a tenant property
  (`environment: "production" | "sandbox"`) set at tenant create. This
  keeps the public OIDC contract clean.
- **Scope mapping for `openid`**: standard OIDC requires `openid` in the
  scope to get an ID token. Toss does not have an `openid` scope. We
  treat `openid` as a bridge-side virtual scope: if the consumer requests
  `openid`, we always honor it (we always issue an ID token). Toss-side
  scope is whatever the user agreed to in the mini-app; we never inject
  scopes the mini-app didn't have. Document in README.
- **Tenant ID = client_id**: do we expose the internal tenant_id as the
  OIDC client_id, or generate them as separate identifiers? Decision:
  same value (`tnt_<24 base32>`). Simpler, no rename hazard. Reconsider
  if the future console wants human-friendly client_ids.

## 11. Out-of-scope decisions revisited

This spec deletes the previously-tracked TODO item "cryptographic
signature verification of the Toss access-token JWT" and updates the
CLAUDE.md "pre-stable gap" framing. The bridge is an adapter; the AT is
opaque to it; `/login-me` (over mTLS) is the validation primitive Toss
documents and we use it. This is now a property of the system, not a gap.

## 12. References

- Apps in Toss developer docs:
  - https://developers-apps-in-toss.toss.im/login/develop.html
  - https://developers-apps-in-toss.toss.im/development/integration-process.html
  - https://developers-apps-in-toss.toss.im/bedrock/reference/framework/로그인/appLogin.html
- Firebase pricing / Spark plan outbound restrictions:
  - https://firebase.google.com/docs/functions/quotas
  - https://firebase.google.com/docs/projects/billing/firebase-pricing-plans
- OIDC core: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7009 (token revocation): https://datatracker.ietf.org/doc/html/rfc7009
- RFC 6749 (OAuth 2.0): https://datatracker.ietf.org/doc/html/rfc6749
