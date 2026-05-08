# RUNBOOK — oidc-bridge

Operational procedures for self-host deployments of the bridge.
Each section is self-contained — read top-to-bottom for the procedure you're
running.

> The community public instance at `oidc-bridge.aitc.dev` runs on Cloudflare
> Workers from a separate repo (`oidc-bridge-cloud`); its operational
> procedures are not covered here.

## First-time setup

For a brand-new self-host install, see [`SELF_HOSTING.md`](./SELF_HOSTING.md)
— it walks through `oidc-bridge bootstrap` and `oidc-bridge doctor` and
the env-var block they produce. The procedures below assume that
walkthrough has already been run.

## Rotating OIDC signing keys

The bridge supports overlapping signing keys. Add the new key first, switch the
active kid, then drop the old key after consumers' JWKS caches expire (typical
TTL: 5 minutes; max observed: 1 hour).

1. Generate a new RSA-2048 PEM (PKCS#8):
   ```bash
   node -e 'import("node:crypto").then(({generateKeyPairSync})=>{const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});process.stdout.write(privateKey.export({format:"pem",type:"pkcs8"}).toString())})' > new-key.pem
   ```
2. Set the new key as `OIDC_SIGNING_KEY_K2_PEM` in your secret store
   (env vars, `.env` file, or whatever your self-host setup uses). On
   second and later rotations, write the new key into whichever slot was
   just retired — see step 6's slot-swap convention. Pick a kid value for
   `OIDC_ACTIVE_KID` later. Convention: short stable slot names for env
   vars (`K1`, `K2`); the kid value carried inside JWKS / `id_token` header
   can be anything (e.g. `2026-05-15-a` — date helps audit). The kid in
   env-var names is uppercased; the registry lowercases it.
3. Restart the bridge **without** changing `OIDC_ACTIVE_KID` (still `k1`).
   The new K2 key is now in JWKS but not yet signing. Verify:
   ```bash
   curl -s https://oidc-bridge.aitc.dev/.well-known/jwks.json | jq '.keys[].kid'
   ```
4. Wait at least 6 hours so consumer JWKS caches see the new kid.
5. Set `OIDC_ACTIVE_KID=k2` and restart. New id_tokens sign with K2.
   Consumers verify with whichever key matches the token's kid.
6. After 24 hours of new-token-only signing, drop the old K1 secret and
   restart. To rotate again later, swap the slots: the now-retired K1 slot
   becomes the home for the next new key.

Need more than two overlapping keys at once? Add an `OIDC_SIGNING_KEY_K3_PEM`
secret in your environment alongside `K1` and `K2`. The bridge reads any
`OIDC_SIGNING_KEY_K<N>_PEM` slot it finds; only the active kid signs. Extra
slots stay optional, so existing deploys keep working when only K1+K2 are set.

## Adding a confidential client (Edge Function operator)

Confidential clients hold a `client_secret` and authenticate `/oidc/token`
calls with `client_secret_basic` or `client_secret_post`. They do **not** use
the `Origin` header for auth.

1. Issue a secret via the admin CLI:
   ```bash
   oidc-bridge app rotate-secret --app-id app_abc
   ```
   The plaintext is shown **once**. Store it in your operator's secret store
   (Supabase Edge Function secret, GCP Secret Manager, etc.).
2. Use `client_secret_basic` from the operator:
   ```ts
   const auth = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
   await fetch(`${BRIDGE}/oidc/token`, {
     method: 'POST',
     headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
     body: new URLSearchParams({
       grant_type: 'authorization_code',
       code: authorizationCode,
       client_id: clientId,
     }),
   });
   ```
3. Rotation overlap: `app rotate-secret` adds a new hash and keeps the old
   one. Both are accepted until you call:
   ```bash
   oidc-bridge app rotate-secret --app-id app_abc --drop-previous
   ```

Confidential clients can have `allowed_origins` empty — Origin is ignored
when an `Authorization: Basic` header is present.

## Enabling raw-tokens for an app

Raw-tokens (`GET /oidc/raw-tokens`) returns the underlying Toss access token.
Default-off; opt in per app:

```bash
oidc-bridge app raw-tokens --app-id app_abc --enable
```

The endpoint never returns the refresh token. To refresh, the operator calls
`/oidc/token grant_type=refresh_token` — Bridge stays the lifecycle authority.

Disable:
```bash
oidc-bridge app raw-tokens --app-id app_abc --disable
```

When disabled, `GET /oidc/raw-tokens` returns 404 — the route looks absent for
that app.

## Revoking tokens

`POST /oidc/revoke` accepts:
- `token=ait_<access_token> token_type_hint=access_token` — local-only mark.
- `token=ait_<refresh_token> token_type_hint=refresh_token` — local mark + Toss `/access-remove`.

Always returns 200. The local revocation list is per-instance in-memory;
restarting the bridge clears it. For a permanent kill switch in self-host,
rotate the master key (the old wrapper version becomes unrecoverable once you
remove the old key bytes).

## Capturing fresh Toss fixtures (`pnpm spike:toss`)

The unit tests under `src/toss/real-adapter.test.ts` use synthetic envelopes.
The `src/toss/fixtures/*.real.json` files are real captured envelopes (with
tokens / userKey / PII redacted). Refresh them whenever Toss changes the
envelope.

Prerequisites:

- A Toss sandbox cert + key (`*.cert.pem`, `*.key.pem`) registered to a
  test app.
- A fresh `authorizationCode` from the mini-app's `appLogin()` (10-minute
  TTL).

Run:

```bash
TOSS_LIVE_CERT_PATH=./local/sandbox.cert.pem \
TOSS_LIVE_KEY_PATH=./local/sandbox.key.pem \
TOSS_API_BASE=https://apps-in-toss-api.toss.im \
TOSS_LIVE_AUTH_CODE=<authorizationCode> \
pnpm spike:toss
```

Five `.real.json` files appear under `src/toss/fixtures/`. **Inspect them
before committing** — confirm no real token, no real userKey, no PII.

## Smoke-testing against sandbox (`pnpm test:e2e:live`)

A single gated test exercises the full happy path against Toss sandbox.
CI never runs it.

```bash
TOSS_LIVE_TEST=1 \
TOSS_LIVE_CERT_PATH=./local/sandbox.cert.pem \
TOSS_LIVE_KEY_PATH=./local/sandbox.key.pem \
TOSS_LIVE_AUTH_CODE=<authorizationCode> \
pnpm test:e2e:live
```

If this passes, the real adapter is wired correctly end-to-end. If it fails
with `upstream_error`, check `apiBase`, cert validity, and that the
authorization code is fresh (10-minute window).

## Session login (preview, opt-in)

`POST /admin/login` and `POST /admin/logout` are **preview endpoints** that
issue a `__Host-bridge_session` cookie. They exist as forward-compatibility
scaffolding for a future multi-user web console. Default behavior is unchanged:
the routes are not registered unless both the env flag is on **and** the
service is wired in `server.ts`. With the flag off, both endpoints return
`404`, indistinguishable from "endpoint does not exist."

**Do not depend on this surface yet.** Admin REST stays `API_TOKEN`-only —
session auth is not accepted on `/admin/*` write paths.

### Set a password (offline; sqlite only)

```bash
oidc-bridge user set-password <email> --db-path ./data/oidc-bridge.sqlite \
  --password 'hunter2'
# or read from stdin (recommended for scripts)
printf 'hunter2' | oidc-bridge user set-password <email> \
  --db-path ./data/oidc-bridge.sqlite
```

The CLI works regardless of whether the feature flag is on. Hash is bcrypt
(cost factor 12) — the same parameters used elsewhere in the bridge.

### Enable the routes

Set `BRIDGE_ENABLE_SESSION_LOGIN=1`, then ensure `server.ts` constructs the
`session` block when the flag is on. Until that wiring exists in the
entrypoint, the flag alone is a no-op — the route module is mounted only when
`createApp({ session: { service } })` is called explicitly.

### Login flow

```bash
curl -i -X POST https://oidc-bridge.aitc.dev/admin/login \
  -H 'content-type: application/json' \
  -d '{"email":"a@x.com","password":"hunter2"}'
# 200 OK
# set-cookie: __Host-bridge_session=<sid>; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=...
```

Cookie attributes are fixed: `__Host-` prefix (RFC 6265bis — protects against
subdomain takeover), `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. The
`Secure` attribute means **session login does not work over plain HTTP** — TLS
is mandatory.

### Expired-session cleanup

`runStartupTasks` purges expired `user_sessions` rows on every boot. There is
no in-process cron — restart cadence sets the cleanup cadence. For long-lived
deployments, a periodic restart (or an external cron calling a future
`/admin/sessions/purge`) is appropriate.

### Logout

```bash
curl -i -X POST https://oidc-bridge.aitc.dev/admin/logout \
  -H 'cookie: __Host-bridge_session=<sid>'
# 200 OK
# set-cookie: __Host-bridge_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0
```

Logout is idempotent — missing or unknown cookie still returns 200 and clears
the cookie on the client.

## When Toss changes the envelope shape

1. `pnpm spike:toss` to capture fresh fixtures.
2. Eyeball the diff in `src/toss/fixtures/*.real.json`.
3. If keys were added, parsing still works (we only consume known fields).
4. If keys were renamed or removed, update `src/toss/real-adapter.ts`
   `toTokenSet` / `loginMe` / `accessRemove` and add a unit test pinning
   the new shape.
5. Open a PR with the fixture refresh + the parser change, never
   separately.

## Status page (`/status`)

- Public, no auth. Returns HTML by default; JSON when `Accept: application/json`
  or `?format=json`.
- Worst-of probes: green / yellow / red.
- Probes: db connectivity, master key fetch, JWKS sign+verify roundtrip,
  last-`/healthz` freshness.
- Operators of the public instance link the status page from the homepage.

## Rate limits

- Per-IP: `RATE_LIMIT_IP_PER_MIN` (default `60`).
- Per-app: `RATE_LIMIT_APP_PER_MIN` (default `600`).
- Sliding-window, in-memory, per-instance (multi-replica deployments do
  not share counters — acceptable for the initial release).
- Toggle entirely with `RATE_LIMIT_ENABLED=false` (e.g. self-host on a
  trusted network).
- Self-hosters behind a single shared NAT will see false-positive
  IP-rate-limit hits; raise `RATE_LIMIT_IP_PER_MIN` or disable.
- `/healthz` and `/status` are exempt.

## Structured logs

- One JSON line per request: `{ time, level, request_id, method, path, status, latency_ms, user_agent, ip_hash }`.
- IPs are sha256-hashed with `IP_HASH_SALT` (random per process unless set explicitly).
- The pino redact list (set up in earlier phases) covers all known
  secret-shaped fields.
- Logs go to stdout. In `docker compose` deployments, `docker compose
  logs -f bridge` shows them. In Cloud Run, Cloud Logging picks them up.
- Inbound `X-Request-Id` headers are honored when they match
  `[A-Za-z0-9_.-]{1,128}`; otherwise a fresh UUID is generated. The id
  is echoed back in the response header and on the log line.

## OpenTelemetry (opt-in)

- Set `OTEL_ENABLED=1` and configure standard OTel envs
  (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, etc.).
- `pnpm install --include=optional` to pull `@opentelemetry/sdk-node` +
  `auto-instrumentations-node`. Without that, the bridge logs a warning
  at boot and continues without tracing.
- The bridge does no OTel-specific code beyond `sdk.start()`; auto-
  instrumentations cover Hono, undici (Toss adapter), and pg.
