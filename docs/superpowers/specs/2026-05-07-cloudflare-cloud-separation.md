# oidc-bridge cloud separation — design spec

Status: approved (2026-05-07, prototype validation session). Supersedes the
self-host single-host operating model defined in the
[zero-code mode design spec (2026-05-01)](./2026-05-01-oidc-bridge-zero-code-mode-design.md).
That spec's API surface, data model, and OIDC behavior remain valid — this
spec only replaces the **deployment topology, mTLS storage model, and tenant
isolation primitives**. The 12-phase implementation plan is paused at Phase 8
(Phase 9 self-host artifacts is cancelled, see §10).

Evidence: [`meta/cloudflare-cloud-separation-prototype.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/meta/cloudflare-cloud-separation-prototype.md) (umbrella, private). All architectural assumptions in this spec were validated end-to-end against production Toss API endpoints (`apps-in-toss-api.toss.im`) using real Toss-issued mTLS certs through Cloudflare Workers for Platforms.

## 1. North star

The bridge's Vultr-host root compromise no longer exposes any tenant's mTLS
private key — because the bridge no longer holds them. Tenant mTLS certs
are stored on Cloudflare and bound per-Worker; the bridge code path never
sees plaintext key material.

This is delivered without giving up the existing operator-friendly properties:

- One issuer URL per tenant (unchanged from zero-code spec).
- Self-host remains a first-class option (OSS).
- Zero-downtime mTLS cert rotation (newly required, validated by prototype).

The operating model changes from **"single Vultr Docker container with
encrypted mTLS in DB"** to **"Cloudflare Workers for Platforms dispatch
namespace + per-tenant user Worker, each with its own mTLS binding."**
Self-host stays available for operators who need it.

## 2. Problem statement

### 2.1 The Vultr threat model

The 2026-05-01 spec stores tenant mTLS certs as ciphertext in the bridge's
SQLite DB, with HKDF-derived sealing keys held in env vars on the same
Vultr host. A host root compromise yields the DB ciphertext, the master
key, and the sealing key in one go — every tenant's mTLS cert is then
decryptable in plain.

This is not a theoretical concern: Vultr Cloud Compute Seoul (`vc2-1c-1gb`,
~$5/mo) is the operating environment for the public instance
(`oidc-bridge.aitc.dev`), and the threat model has to assume host
compromise is the most likely failure mode.

### 2.2 What "cloud separation" means

Move the cert store off the bridge host entirely. The bridge code, on
whatever host runs it, must:

1. Never see a plaintext private key for a tenant.
2. Be unable to read a private key back even with full DB access.
3. Be able to use a tenant's cert for outbound mTLS without holding it.
4. Rotate certs with zero downtime (Toss requires this — see 2.3).

Cloudflare Workers' mTLS binding (`{type:"mtls_certificate"}`) gives us
exactly this: cert/key are stored at the account level, write-only after
upload; Workers receive an opaque binding handle that exposes only
`fetch()`. The Worker code cannot read the cert's bytes.

### 2.3 Toss's rotation requirement

Toss-issued mTLS certs have a 390-day lifetime. The 통합 프로세스
documentation explicitly supports issuing multiple active certs per
mini-app for **무중단 rotation**. Prototype validated this: two certs
issued for `aitc-sdk-example` (`miniAppId=31146`) were both `status:
ENABLED` simultaneously, and both passed mTLS handshake against
`apps-in-toss-api.toss.im` (errorCode 4050, application-layer business
error — TLS layer accepted both).

Rotation must therefore be zero-downtime by design, not best-effort.

## 3. Architecture

### 3.1 Two-layer Worker model

```
client → dispatcher Worker (top-level)
       → env.NS.get(tenantId).fetch()
       → tenant Worker (dispatch namespace)
       → env.TOSS_MTLS.fetch(toss endpoint)
       → apps-in-toss-api.toss.im
```

**Dispatcher Worker** (`oidc-bridge-dispatcher`):

- Top-level Worker on `oidc-bridge.aitc.dev`.
- Holds: `[[dispatch_namespaces]] binding = "NS"`.
- Routes incoming OIDC requests by tenant. Routing key candidates:
  hostname (`<tenantId>.oidc-bridge.aitc.dev`), path prefix
  (`/t/<tenantId>/oidc/...`), or a tenant resolver that maps `client_id`
  in the request to a Worker name. Path prefix is the prototype-validated
  pattern; final routing key chosen in §4.
- Holds zero tenant secrets. Cannot see any tenant's cert. Compromise of
  the dispatcher discloses only routing logic.

**Tenant Worker** (`oidc-bridge-tenant-<tenantId>`):

- Lives in the `oidc-bridge` dispatch namespace.
- Bindings (per-tenant, baked into Worker metadata at deploy time):
  - `TOSS_MTLS` — `mtls_certificate` binding to the active Toss cert.
  - `TOSS_MTLS_NEW` — `mtls_certificate` binding present only during
    rotation overlap.
  - `DB` — `d1` binding to the tenant's own D1 database (hosts OIDC
    state: codes, refresh tokens, JWKS keys, audit log).
  - `SIGNING_KEY` (or split set) — `secret_text` for OIDC id_token
    signing.
  - `ACTIVE_BINDING` — `secret_text`, value `"TOSS_MTLS"` or
    `"TOSS_MTLS_NEW"`. Read by application code to choose which mTLS
    binding to use; the toggle that drives zero-downtime rotation
    (see §5).

Each tenant Worker only has access to its own bindings. A different
tenant's Worker exists in the same namespace but they cannot reach each
other's bindings — neither cert handle, nor D1, nor signing keys
(prototype-validated isolation, see evidence doc § Worker 간 격리 모델).

### 3.2 What replaces the Vultr DB

Per-tenant D1 instead of one shared SQLite file. Each tenant's D1 schema
matches the existing zero-code schema (codes, refresh_tokens,
authorization_requests, signing_keys), minus the
`tenants`/`mtls_certificates` tables — those are replaced by Worker
metadata (cert binding) and a control-plane registry on the dispatcher
(see §4.1).

This sharding is administrative, not for performance. It keeps tenant
data physically isolated at the storage layer — a tenant Worker cannot
even name another tenant's D1 binding because the binding is created
per-Worker by metadata, not discoverable.

### 3.3 What stays the same

OIDC surface from the zero-code spec is unchanged: `/oidc/.well-known/*`,
`/oidc/authorize`, `/oidc/token`, `/oidc/userinfo`, `/oidc/revoke`. The
OIDC code is the same. Only its host (tenant Worker, not single-process
Hono server on Vultr) and its outbound mTLS adapter change.

`@/runtime` abstraction layer in the bridge code:

```ts
interface MtlsClient {
  fetch(input: RequestInfo, init?: RequestInit): Promise<Response>;
}
```

- Self-host implementation: `undici.Agent` with cert/key from env.
- Cloud implementation: `env.TOSS_MTLS` (CF mTLS binding).

The Hono app already runs runtime-agnostic on Node + Workers; the only
Node-specific dependency in the existing zero-code phases is undici, which
gets dependency-injected at the runtime boundary (see §6.2 for migration
detail).

## 4. Control plane

### 4.1 Tenant registry

The dispatcher Worker no longer issues OIDC traffic itself, but it still
needs to know which tenant Workers exist. The registry lives in the
dispatcher's own D1:

```sql
CREATE TABLE tenants (
  tenant_id TEXT PRIMARY KEY,        -- slug, used as Worker name suffix
  display_name TEXT NOT NULL,
  cf_account_id TEXT NOT NULL,       -- which CF account hosts the tenant
                                     -- Worker; defaults to primary account.
                                     -- Present from day 1 to make multi-
                                     -- account sharding a router-level
                                     -- change later (see §7.2).
  worker_name TEXT NOT NULL,         -- "oidc-bridge-tenant-<slug>"
  active_cert_binding TEXT NOT NULL, -- "TOSS_MTLS" | "TOSS_MTLS_NEW"
  active_cf_cert_id TEXT NOT NULL,
  rotation_state TEXT NOT NULL DEFAULT 'idle',
                                     -- 'idle' | 'overlap' | 'soak' | 'cleanup'
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

The dispatcher writes this only via the admin path. The tenant Workers
themselves do not read this table — they get `ACTIVE_BINDING` from their
own metadata, refreshed at each deploy.

### 4.2 Admin operations

Admin operations are HTTP endpoints on the dispatcher with bearer-auth
(operator credential). They drive the CF API:

- `POST /admin/tenants` — register a new tenant. Allocates D1, deploys
  tenant Worker with placeholder bindings, registers in the registry.
- `POST /admin/tenants/:id/cert/upload` — upload a Toss-issued cert
  (PEM + key, multipart). Calls `POST /accounts/{acct}/mtls_certificates`,
  updates Worker metadata to point `TOSS_MTLS` (first cert) or
  `TOSS_MTLS_NEW` (overlap) at the new cert id.
- `POST /admin/tenants/:id/rotate` — drive the rotation state machine
  (§5).
- `DELETE /admin/tenants/:id` — tear down (Worker delete → D1 delete →
  cert delete after the in-use protection clears).

The admin path holds the only CF API token with cert-write scope. That
token is the cloud-mode equivalent of the Vultr master key — but unlike
the master key, it cannot be used to read cert bytes back (see threat
model below).

### 4.3 Operator UX

Same surface as the zero-code phase 2 admin UI, plus:

- Cert upload form takes a `.pem`/`.key` pair downloaded from the Toss
  console (or pasted directly).
- Rotation button triggers the §5 state machine; UI shows rotation_state
  with a progress strip and a 30-second post-deploy "stabilizing" hint
  (validates the prototype's measured ~21s isolate-warm window).
- Self-host operators don't see the cloud-specific UI — runtime detection
  hides the cert-upload path and falls back to the existing env-var-based
  cert config.

## 5. Zero-downtime rotation

Rotation is a 5-step state machine. Each step is idempotent. Resuming a
half-failed rotation is supported by replaying from the registry's
`rotation_state`.

### 5.1 State machine

```
idle → overlap → soak → cleanup → idle
```

#### Step A: idle → overlap (Toss cert issuance + CF upload + binding add)

1. Operator: issue a new cert in the Toss console (or via console-cli:
   `aitcc app certs issue <miniAppId> --name <new-cert-name>`).
2. Admin uploads the new cert to CF (`POST /mtls_certificates`).
3. Admin updates tenant Worker metadata: keep `TOSS_MTLS` →
   old_cf_cert_id, add `TOSS_MTLS_NEW` → new_cf_cert_id, leave
   `ACTIVE_BINDING = "TOSS_MTLS"`.
4. Registry: rotation_state = `overlap`.

State invariant: both bindings live, traffic still 100% old cert,
application path unchanged. Prototype measurement: this PUT script step
took 1153ms, both bindings active immediately.

#### Step B: overlap → soak (application toggle)

1. Admin updates tenant Worker metadata: flip
   `ACTIVE_BINDING = "TOSS_MTLS_NEW"`. (No mtls_certificate change.)
2. Registry: `rotation_state = soak`.

State invariant: traffic switches to the new cert at the application
layer. Prototype measurement: 80 polls @ 100ms during this transition
showed 79/80 successful application-layer responses (one transient
isolate cold start). Zero outbound failures because both certs remain
bound and either is accepted by Toss.

#### Step C: soak (wait window, observe)

Default soak window: 60s. Operator may configure 0–600s. During soak the
admin UI shows live error rate from D1 audit log; one-click rollback
flips `ACTIVE_BINDING` back.

#### Step D: soak → cleanup (drop old binding)

1. Admin updates tenant Worker metadata: remove `TOSS_MTLS_NEW`, set
   `TOSS_MTLS = new_cf_cert_id`, `ACTIVE_BINDING = "TOSS_MTLS"`.
2. Registry: `rotation_state = cleanup`.

State invariant: tenant Worker ends in single-binding state pointing at
the new cert. Application code path is identical to before rotation
started.

#### Step E: cleanup → idle (drop old certs)

1. Admin deletes the old CF cert (`DELETE /mtls_certificates/{old_cf_id}`).
   CF responds with `code: 1476 "Certificate cannot be deleted while in
   use"` until edge propagation clears the old binding reference.
   Retry-with-backoff (prototype: 4-second sleep between attempts; cleared
   by iter 2).
2. Operator revokes the old Toss cert in the console (or via console-cli:
   `aitcc app certs revoke <oldCertId>`).
3. Registry: `rotation_state = idle`.

### 5.2 Why this is strictly zero-downtime

Three independent properties make this true:

- **Toss accepts both certs simultaneously** during the overlap window
  (validated end-to-end against production endpoint).
- **CF mTLS binding swap is non-atomic but never leaves a Worker without
  a valid binding** — the metadata PUT is read-then-replace, and the
  isolate uses whichever binding state is current. There is no "between
  binding" moment where outbound fails.
- **The cutover is at the application layer** (one secret_text flip), not
  at the cert-binding layer. The CF binding race window (~1.5s observed)
  is invisible to user-facing requests because both bindings remain valid
  throughout.

If any one of the above fails — Toss rejects dual-cert, CF binding swap
becomes unsafe, or the application toggle takes >5s to stabilize — the
rollback is a single metadata PUT.

### 5.3 Self-host rotation

Same state machine, different primitives:

- "Upload to CF" → place new PEM + key on disk.
- "Add NEW binding" → load a second `undici.Agent` in memory, register
  it under a `new` slot in the runtime registry.
- "Toggle ACTIVE_BINDING" → flip a config flag (env var reload or admin
  POST). Worker process keeps both Agents alive during overlap.
- "Drop old binding" → unload the old Agent, await its inflight requests,
  then delete its key files.

The bridge process is runtime-agnostic; the rotation state machine maps
1:1.

## 6. Repo and code structure

### 6.1 New private repo: `oidc-bridge-cloud`

A separate **private** repo for the dispatcher Worker, control-plane admin
endpoints, and CF API integration code. Held private because:

- It encodes the operator's CF account-level configuration (account id,
  dispatch namespace name, D1 naming convention, API token issuance flow).
- It is not part of the OSS surface — the OSS path is self-host, which
  needs only the existing `oidc-bridge` repo.

Repo skeleton:

```
oidc-bridge-cloud/
├─ wrangler.toml          # dispatcher Worker config
├─ src/
│  ├─ dispatcher.ts       # NS routing + admin auth
│  ├─ admin/
│  │  ├─ tenants.ts       # CRUD + cert upload + rotation drive
│  │  ├─ cf-api.ts        # CF API client (cert upload, Worker PUT, D1)
│  │  └─ registry.ts      # tenant registry D1 access
│  └─ runtime/             # shared with oidc-bridge: same Hono app,
│     └─ index.ts         # different runtime boundary
└─ README.md              # operator-only, points to oidc-bridge OSS
```

The `oidc-bridge` repo (public, OSS) gets a runtime adapter so the same
Hono app code runs on both:

```
oidc-bridge/
├─ src/
│  ├─ runtime/
│  │  ├─ node.ts          # undici-based mTLS client, SQLite/Postgres
│  │  ├─ workers.ts       # mtls_certificate binding-based client, D1
│  │  └─ index.ts         # interface
│  └─ ...                 # OIDC, Hono routes — runtime-agnostic
```

### 6.2 Hono runtime-agnostic migration

The current zero-code phase 5+ code uses `undici.Agent` directly inside
the Toss adapter. Migration to runtime-agnostic:

1. Define `MtlsClient` interface (3 methods: `fetch`, `dispose`, `tag`).
2. Add Node implementation (existing undici code, behind interface).
3. Add Workers implementation (`env.TOSS_MTLS.fetch`).
4. Replace direct undici calls with the interface throughout the Toss
   adapter.
5. Switch all stored crypto from Node `crypto` to `WebCrypto` async API
   (signing keys, JWT). Most of this is already in zero-code phase 5.

This is the only meaningful code change required by cloud separation.
Everything else (OIDC routes, JWKS, admin UI) is already runtime-portable.

## 7. Cost and capacity

### 7.1 Cloud mode

| Item | Cost |
|---|---|
| Workers Paid | $5/mo (one per CF account) |
| Workers for Platforms | $25/mo (one per CF account) |
| Per-Worker request cost | $0.30 / 1M requests (Workers Paid) |
| D1 (per-tenant) | $5/mo includes 5GB; sufficient for thousands of tenants |
| mTLS cert storage | included |
| Custom hostname (`oidc-bridge.aitc.dev`) | $0 (CF Registrar) |
| **Floor** | **$30/mo** |

Vs. Vultr: $5/mo VPS. Cloud mode is +$25/mo for the WfP subscription,
plus per-tenant D1 cost which is rounding error.

### 7.2 Capacity bounds and sharding plan

**Workers mTLS cert per-account limit: 1,000.** The number is stated in
the [mTLS Workers launch blog post](https://blog.cloudflare.com/mtls-workers/)
("There's a limit of 1,000 certificates that can be uploaded per
account. Contact your account team or reach out through the Cloudflare
Developer Discord if you need more certificates.") but is not present
on `developers.cloudflare.com/workers/platform/limits/`, the WfP limits
page, or the mtls_certificates API reference. We treat the blog as
authoritative.

At 2 certs/tenant during overlap rotation, the effective ceiling is
**approximately 500 concurrent tenants per CF account**. Idle steady
state is 1 cert/tenant = 1,000 tenants, but rotations cluster (we don't
want a fleet rotation pattern that needs >500 tenants briefly).

Direct verification attempts that informed the above:

- **API headers**: `GET /accounts/{id}/mtls_certificates` returns no
  quota hint. Only rate-limit headers (`q=1200;w=300` for API calls).
- **Push test (5 unique CA certs)**: all 5 uploads returned `success:
  true` with no quota-exceeded signal. Consistent with the 1,000 ceiling.
- **Adjacent endpoint distinction**: Cloudflare One Account Limits lists
  "mTLS root certificates: 50 per account" but that covers `POST
  /access/certificates` (Zero Trust inbound mTLS CA validation), a
  different endpoint and almost certainly a different store from
  `/accounts/{id}/mtls_certificates` (Workers outbound mTLS).
- **Limit increase channel**: not Enterprise-gated. Workers Paid + WfP
  customers can submit
  [Cloudflare's general limit increase form](https://docs.google.com/forms/d/e/1FAIpQLSd_fwAVOboH9SlutMonzbhCxuuuOmiU1L1oqaB1PnWTkSE6zg/viewform).

Other capacity bounds (documented):

- WfP scripts per account: **unlimited** for WfP customers (overrides the
  Workers Paid 500-script cap). Tenant Worker count is not gated.
- Per-Worker `mtls_certificate` binding count: not documented. Two are
  fine (validated). The 128 environment-variable cap is unrelated.

Architecture implication — the CF-recommended pattern is one shared CA
cert in `/mtls_certificates` plus per-tenant leaf certs (which are
unlimited within the CA). **That pattern is structurally inapplicable
here.** It assumes the operator can choose a CA whose certs the origin
trusts — i.e. the origin must add the operator's CA to its trust store.
Toss-side mTLS only accepts certs issued by its own internal root
(`Toss appsintoss Root CA`); we cannot upload our own CA and have Toss
trust it. So every tenant occupies one cert-store slot (two during
overlap rotation), and the recommended-pattern fallback is unavailable.

Plan: submit the limit increase form before crossing **400 tenants**
(80% of the 500-tenant ceiling). Re-test at 50, 200, and 400 to confirm
the blog-stated ceiling has not changed silently. Beyond ~1000 tenants,
multi-account sharding is required.

#### Multi-account sharding — design assumptions baked in from Phase 10c

Cross-account sharding is **not free**. Service bindings (`env.NS.get()`)
are same-account only:

> "Service bindings require that the target Worker must be on your Cloudflare account."

A dispatcher in account A cannot directly invoke a tenant Worker in
account B via service binding; it has to fall back to HTTP fetch (~50ms
RTT vs. ~1ms in-account). To keep that future migration as a router-level
addition rather than a schema migration under production load, we bake
in four design choices from the start:

1. **`tenants.cf_account_id`** column from Phase 10c, with `DEFAULT
   '<primary_account_id>' NOT NULL`. Existing rows unaffected; sharded
   rows just carry a different value.
2. **Account-aware CF API client factory**. `getCfClient(accountId)` is
   the only way to obtain a CF API client. Initial implementation
   ignores `accountId` and returns the primary token; interface stays
   stable when shard tokens are added.
3. **`invokeWorker(tenantId, request, registry)` abstraction** in the
   dispatcher. Initial implementation: `env.NS.get(workerName).fetch()`.
   Sharded implementation: branch on `cf_account_id` and HTTP-fetch into
   the shard account's dispatcher. External signature unchanged.
4. **Token storage convention**: dispatcher reads either
   `CF_API_TOKEN_ACCOUNTS` (JSON map) or
   `CF_API_TOKEN_<ACCOUNT_SLUG>` env vars. Single-account operators set
   one entry; sharded operators add per-account tokens without code
   changes.

The OIDC issuer URL stays `oidc-bridge.aitc.dev` regardless of which
shard a tenant lives on — the primary-account dispatcher always answers
on that hostname and proxies to the shard. Tenants and downstream
clients (Supabase / Firebase / etc.) see no change.

**Cost of sharding**: +$30/mo per additional CF account (WfP $25 +
Workers Paid $5). At 500 tenants/shard, this is $0.06/tenant/mo —
rounding error vs. request and D1 costs.

## 8. Threat model

### 8.1 Cloud-mode threat surface

| Adversary | Self-host (Vultr) | Cloud (this spec) |
|---|---|---|
| Vultr/host root compromise | All tenant certs decryptable | No cert plaintext on host |
| CF API token leak (cert-write scope) | n/a | Attacker can route any cert to a Worker they control. Cert plaintext **still not retrievable** (write-only API). |
| Tenant Worker A compromise (e.g. RCE in tenant code) | n/a (single process) | A can call `env.TOSS_MTLS.fetch()` only with its own cert. Cannot read cert bytes. Cannot reach tenant B's bindings. |
| Operator laptop compromise | Yes — env vars + DB master key on disk | Yes — CF API token in 1Password. Mitigated by Touch ID + token scope split. |
| Toss-side compromise | Tenant cert blast radius | Tenant cert blast radius (unchanged) |

### 8.2 Mitigations

- **CF API token scope split**: dispatcher's runtime token has only
  `Workers KV / D1 / Read` for the registry. Cert-write token is
  separate, used only from the admin laptop, stored in 1Password,
  rotated quarterly.
- **Audit log**: all admin operations write to an append-only D1 table
  (operator identity, timestamp, tenant, action). Compromise becomes
  detectable.
- **Per-Worker D1**: a tenant Worker compromise can read only its own
  D1; the tenants table on the dispatcher is unreachable from inside
  any tenant.

## 9. Self-host preservation

Self-host remains a fully supported deployment mode. Reasons:

- OSS principle: `oidc-bridge` is community-operated, MIT-licensed; users
  must be able to run it without a cloud account.
- Firebase Spark plan: cloud mode requires a paid CF account, which not
  all users have. Self-host stays the universal path.
- Threat-model preference: some operators prefer "I own the host" over
  "I trust Cloudflare's mTLS storage." This spec doesn't argue against
  that preference.

The self-host path uses the same codebase (runtime-agnostic Hono app),
the same Docker image, the same `docker-compose.yml`, the same
zero-code OIDC surface. Only the mTLS adapter and storage differ at
runtime, swapped at the `@/runtime` boundary.

The 2026-05-01 Phase 9 ("self-host artifacts") is **cancelled** in its
original form (Vultr-specific Docker compose + Caddy). It will be
reborn as a smaller phase that produces a generic Docker image + a
docker-compose example, without the production-deploy automation that
was specific to Vultr.

## 10. Phase plan (replaces Phases 9–11 of the 2026-05-01 plan)

The 2026-05-01 zero-code plan had 12 phases (00–11). Phases 0–8 are kept
as-is — they produce the OIDC code, admin UI, sessions, and observability
that this spec inherits. Phase 9 is cancelled (Vultr-specific). The new
plan replaces 9–11:

| Phase | Title | Output | Status |
|---|---|---|---|
| 09c | Runtime abstraction | `MtlsClient` + `Storage` interfaces; Node + Workers implementations behind the same Hono app | ✅ merged ([oidc-bridge#44](https://github.com/apps-in-toss-community/oidc-bridge/pull/44)) |
| 10c | `oidc-bridge-cloud` private repo skeleton | Dispatcher Worker, admin endpoints stub, CF API client, tenant registry D1 | ✅ merged ([oidc-bridge-cloud#1](https://github.com/apps-in-toss-community/oidc-bridge-cloud/pull/1)) |
| 11c | Tenant Worker template + DNS cutover + Vultr decommission | One-Worker-per-tenant deployment automation; first canary tenant (`aitc-sdk-example` 31146) running on cloud; `oidc-bridge.aitc.dev` cutover to dispatcher Worker; Vultr Seoul VPS destroyed. **Folds the originally-separate Phase 13c (dual-cloud cutover) and Phase 14c (Vultr decommission) into a single phase** because the Vultr public instance had zero real users — dual-cloud staging added drag without reducing risk. | ✅ merged ([oidc-bridge-cloud#3–#10](https://github.com/apps-in-toss-community/oidc-bridge-cloud/pull/3), [oidc-bridge#48](https://github.com/apps-in-toss-community/oidc-bridge/pull/48)) |
| 12c | `MtlsClient` binding + `/oidc/token` GA | Workers `MtlsClient` adapter using the CF `mtls_certificate` Fetcher binding; vendored OIDC token pipeline + Toss adapter wired into the tenant template; per-tenant D1 schema (`apps`, `audit_log`, `revoked_tokens`); the 501 stubs at `/oidc/token`/`/oidc/userinfo`/`/oidc/revoke` replaced with real handlers; sandbox e2e against Toss using the canary's bound cert. | ⬜ in-flight |
| Rotation | Rotation state machine + admin UI | `/admin/tenants/:id/rotate` end-to-end with the §5 state machine; soak/rollback UX. **Originally numbered 12c**; renamed to a non-numbered later phase because 12c was retargeted to `/oidc/token` GA (the launch-blocking work) once 11c absorbed 13c/14c. | ⬜ planned |
| Self-host | Self-host generic Docker | Stripped-down Phase 9 redux: image + compose example, no Vultr automation. **Originally numbered 13c**; deferred behind Rotation because the existing self-host artifacts in `oidc-bridge` repo (preserved through 11c PR #48) already work for the small number of self-host operators. | ⬜ deferred |
| **M5** | **sdk-example dog-food on cloud (launch gate)** | Canary tenant 31146 becomes the production target for sdk-example. Replaces the M5 launch gate from the 2026-05-01 spec. Gates on 12c. | ⬜ planned |

Phase numbering uses `c` suffix where it's still meaningful. The originally-
planned 13c (dual-cloud) and 14c (Vultr decommission) numbers are retired —
both fold into 11c. The Rotation and Self-host phases are kept named (not
numbered) so the umbrella TODO and the spec stay in sync without a global
re-numbering exercise.

## 11. Open questions

These do not block spec acceptance; they block specific later phases.

1. **CF mTLS cert quota silent change** (informs post-launch scale; originally tagged "Phase 13c+").
   Ceiling is 1,000/account per the launch blog post (see §7.2), absent
   from official limits docs. Re-test at 50, 200, and 400 tenants to
   confirm the figure has not changed silently. Submit the limit
   increase form before crossing 400.
2. **Tenant routing key** (blocks Phase 10c). Hostname (subdomain per
   tenant) vs. path prefix vs. client_id resolver. Path prefix is the
   prototype-validated default; hostname is operationally cleaner for
   OIDC `iss` URLs. Decide in Phase 10c against actual Supabase/Firebase
   integration testing.
3. **Admin auth** (blocks Phase 10c). Bearer token with rotation? mTLS
   client cert for the operator? Open.
4. **Dispatcher tenant resolver caching** (blocks Phase 11c). The
   `client_id → tenant_id` lookup is hot path for `/oidc/token`; needs to
   be either inlined in metadata (no DB read) or cached in Workers KV.
5. **Cert generation latency on first registration** (blocks Phase 11c).
   New tenant onboarding requires Toss console cert issuance, which is
   manual today. console-cli automates the API call but does not
   automate the human-in-the-loop console session. UX TBD.

## 12. Acceptance signal

This spec is accepted when:

- An operator can register a new tenant via the admin UI.
- The tenant gets a `oidc-bridge.aitc.dev` issuer URL.
- Supabase configured with that issuer URL accepts an id_token signed by
  the tenant Worker's signing key.
- A complete rotation cycle runs end-to-end with zero observed user-path
  failures (audit log shows no 5xx during the soak window).
- Cleanup of the old cert succeeds within 30s of `cleanup` state entry.

The first tenant to clear all five is `aitc-sdk-example` (`miniAppId
31146`). That is the cloud-mode launch gate, replacing the M5 launch
gate from the 2026-05-01 spec.
