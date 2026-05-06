# Phase 11 Implementation Plan — sdk-example dog-fooding (M5 launch gate)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the legacy `POST /verify` `AuthPage` in the sibling `sdk-example` repo with a Supabase-only flow that exercises the public bridge end-to-end: mini-app calls `appLogin()` → mini-app POSTs to `https://oidc-bridge.aitc.dev/oidc/token` → mini-app calls Supabase `signInWithIdToken(id_token)` → subsequent Supabase calls use the issued Supabase JWT. A "show me Toss claims" button calls `/oidc/userinfo` with the sealed `ait_access_token`. Successful E2E in production is the M5 launch gate; once green, the public instance is "launched" and the milestone closes. **Cross-repo work ships as separate PRs**, so this plan splits into a `sdk-example` PR (nine of the tasks) and a companion `oidc-bridge` PR (two tasks: register the production app, add the prod-smoke crontab). Run them sequentially: bridge-side prep first, then sdk-example wiring, then the production smoke gate.

**Architecture:** sdk-example's `AuthPage` becomes a Supabase-only React component. `appLogin()` returns `{ authorizationCode, referrer }`; the page POSTs that to `/oidc/token` with `grant_type=authorization_code`, `client_id=<sdk-example-client-id>`, no `client_secret` (public client; the bridge's CORS-validated `Origin` allowlist authenticates), and a stable `code_verifier` derived from a session-scoped random `code_challenge` (PKCE optional per spec decision #9 but used here as defense-in-depth). The response carries `id_token` (RS256) + `access_token` (`ait_<base64url>`) + `refresh_token` (`ait_<base64url>`); the page hands `id_token` to `supabase.auth.signInWithIdToken({ provider: 'toss', token: id_token })` per Supabase's third-party-OIDC protocol, with the bridge's issuer (`https://oidc-bridge.aitc.dev`) configured as a third-party provider in the Supabase project. The page stashes the sealed access_token in `sessionStorage` (mini-app reload survives) and uses it on the "show me Toss claims" button to call `/oidc/userinfo`. Refresh runs through the bridge: when Supabase rejects expired tokens, the page POSTs `{ grant_type: 'refresh_token', refresh_token, client_id }` to `/oidc/token` and re-runs `signInWithIdToken` with the fresh `id_token`. Production E2E lives in this repo as a Playwright test gated by `BRIDGE_PROD_E2E=1` and runs nightly via GitHub Actions cron.

**Tech Stack:** Existing sdk-example stack — React 18 + Vite + `@apps-in-toss/web-framework` SDK + `@supabase/supabase-js` v2 + Playwright (already present per sdk-example repo conventions). New in sdk-example: a thin `bridge-client.ts` wrapper that does the OIDC dance. Companion in this repo: `pnpm bridge tenant create` against the production admin (one-time), a tiny GitHub Actions cron workflow that runs the Playwright spec daily, and a `docs/LAUNCH.md` that captures the launch checklist. Supabase third-party-OIDC provider config goes through the Supabase dashboard or CLI; that's operator setup, not code.

---

## Universal invariants (apply to every task in this plan)

These are non-negotiable. Any task that violates one is rejected at review and reworked.

1. **TDD where there is application code.** sdk-example's `bridge-client.ts` is unit-tested against `msw` mocks of `/oidc/token` and `/oidc/userinfo` — failing tests first, then the implementation. Playwright specs are end-to-end and acceptance-driven; they assert observable behavior, not implementation details.
2. **No PII in logs.** sdk-example's browser console must not log id_token, access_token, refresh_token, Supabase JWT, or any field from `/oidc/userinfo`. Tests assert that calling `bridge-client` with a fake fetch produces no `console.log` lines containing `Bearer`, `eyJ`, or `ait_`.
3. **Bridge never spontaneously calls Toss.** sdk-example only triggers a Toss call by user action (clicking "Login" or "show me Toss claims"). No silent prefetch, no warmup ping. The "show me Toss claims" handler shows a toast on click; the network request is bound to the handler, not to mount.
4. **Toss refresh_token never leaves the sealed wrapper.** sdk-example never receives a Toss-shaped JWT. Tests assert that what's persisted in `sessionStorage.refresh_token` matches `/^ait_[A-Za-z0-9_-]+$/` and never matches `/^eyJ/` (JWT shape).
5. **Public clients use Origin, not client_secret.** sdk-example's `bridge-client` POSTs to `/oidc/token` with `client_id` only — never a `client_secret`. The bridge admin entry for sdk-example registers `Origin: https://sdk-example.aitc.dev` (or the local dev origin during development) in the strict-equality allowlist; CORS preflight + same-origin-policy + the bridge's `Origin` validation are the three layers of authentication.
6. **mTLS material never returns from any GET.** Phase 4 covers this. sdk-example's `/oidc/userinfo` round trip in Task 6 asserts the response body has the expected userinfo fields and *does not* contain `mtls_cert_pem`, `mtls_key_pem`, or `client_secret` (defensive — the bridge would never put them there, but the test is cheap).
7. **Cloud-agnostic.** sdk-example does not import `@google-cloud/*`. The bridge URL is a string config; sdk-example does not care that it's hosted on Cloud Run.
8. **Self-host first-class.** Setting `VITE_BRIDGE_URL=http://localhost:8080` in `.env.local` and `VITE_SUPABASE_URL=...` plus a self-hosted Supabase URL must work. The Playwright spec runs against `BRIDGE_BASE_URL` (default `https://oidc-bridge.aitc.dev`) so the same spec exercises self-host or production.
9. **Backwards compatibility — none.** The legacy `POST /verify` `AuthPage` is *replaced*, not augmented. There's no `?legacy=1` toggle. Anyone running an old sdk-example deploy upgrades by pulling the new code. No "deprecated" banner — the bridge endpoint is gone (Phase 4 removed it) and the new flow is the only flow.
10. **No silent fallbacks.** If Supabase third-party-OIDC is misconfigured, the page surfaces the error to the user as a visible message; it does not fall back to anonymous auth or hide the error.
11. **Timing-stable assertions.** Playwright specs use `page.waitForResponse` and `page.waitForFunction`, never `page.waitForTimeout`. CI flakes here are unacceptable on the launch gate.
12. **Cost discipline.** The nightly cron Playwright run calls real Toss + real Supabase. The mini-app authorization code is a 10-minute-TTL value from `appLogin()`; producing one in CI requires a logged-in Toss session. The cron uses a stored long-lived dev account session via Playwright `storageState` (committed encrypted with `git-crypt` — operator setup) so the cron does not require an interactive Toss login. If the cron starts failing because of session expiry, the responsible operator refreshes `storageState` rather than disabling the cron.
13. **No new dependencies in this repo.** Phase 11 work in the bridge repo (Tasks 1–2 and 10–11) is admin CLI invocations + a workflow YAML. No `pnpm add`. sdk-example may add Playwright browsers if it doesn't already have them.

When a step says "verify with X", run X verbatim and confirm the expected output. Don't move on if it doesn't match.

---

## Files touched this phase

This phase splits across **two repos**. Each repo gets its own PR.

### In `oidc-bridge` (this repo)

```
docs/
  LAUNCH.md                                    # CREATE — M5 launch checklist + post-launch ops
  RUNBOOK.md                                   # MODIFY — add "M5 launch verification" section
.github/workflows/
  prod-e2e.yml                                 # CREATE — nightly cron that runs the sdk-example
                                               #   Playwright spec against the prod bridge URL
test/e2e/
  prod-mini-app.spec.ts                        # CREATE — Playwright spec; runs gated by
                                               #   BRIDGE_PROD_E2E=1, also invoked by the cron
playwright.config.ts                           # CREATE — minimal config for the prod-e2e workflow
package.json                                   # MODIFY — add scripts: e2e:prod, e2e:prod:headed
```

### In `sdk-example` (sibling repo)

```
src/auth/
  bridge-client.ts                             # CREATE — typed client for /oidc/token + /oidc/userinfo
  bridge-client.test.ts                        # CREATE — unit tests with msw
  pkce.ts                                      # CREATE — code_verifier + code_challenge helpers
  AuthPage.tsx                                 # REPLACE — Supabase-only flow
  AuthPage.test.tsx                            # CREATE — render + click tests with msw
  TossClaimsButton.tsx                         # CREATE — "show me Toss claims" component
src/lib/
  supabase.ts                                  # MODIFY — wire signInWithIdToken third-party provider
.env.example                                   # MODIFY — add VITE_BRIDGE_URL, VITE_BRIDGE_CLIENT_ID,
                                               #   document VITE_SUPABASE_URL + ANON_KEY
README.md                                      # MODIFY — auth section: replace POST /verify with new flow
```

This is the only set of files this phase touches. Anything not on these lists is out of scope; do not touch it.

---

## Pre-flight: read these once before starting

Before you begin Task 1, do this in order. It's about twenty minutes and prevents the rework that comes from missing a piece of context.

1. Read the spec sections:
   - §3.1 "In scope" bullet "sdk-example dog-fooding integration (this gates M5 launch)".
   - §11 "Phase 11" — the five-bullet scope statement this plan expands.
   - Decision row #3 — sealed Bridge AT is the mini-app re-auth token; no second token format.
   - Decision row #7 — public client auth = strict-equality `Origin` allowlist.
   - Decision row #15 — Toss raw tokens via opt-in `/oidc/raw-tokens` (NOT used in this phase).
2. Read this repo's Phase 4 plan to confirm:
   - Public-client `/oidc/token` accepts `Origin: <allowed>` instead of client_secret.
   - `/oidc/userinfo` is `GET` with `Authorization: Bearer ait_<...>`.
   - PKCE is supported (S256 challenge method).
3. Read the [Supabase third-party OIDC docs](https://supabase.com/docs/guides/auth/social-login/auth-thirdparty) once. The integration model: bridge issuer URL is registered in Supabase's auth settings; Supabase fetches `/.well-known/openid-configuration` and `/.well-known/jwks.json` to verify id_tokens. `signInWithIdToken({ provider: 'toss', token: id_token })` is the call shape — sdk-example needs the bridge's `iss` and `aud` to match what's configured in Supabase, which Phase 10 already arranged.
4. Read sdk-example's current `AuthPage.tsx` (sibling repo) to know exactly what's being replaced. Capture the existing component's surface (props, callbacks, side effects) so the replacement maintains compatible navigation/state behavior even though the auth call changes.
5. Verify Supabase project state: a project exists, third-party OIDC is *not yet configured* with the bridge issuer (this phase configures it in Task 8), and there is at least one test user table or RLS-protected resource the spec can touch to verify "subsequent Supabase API calls use the resulting Supabase JWT" (spec §11 bullet 4).

When that's done, start Task 1.

---

## Task 1 (`oidc-bridge` repo): Register the sdk-example production app

This is one-shot operator work in the bridge repo, **executed against the
production admin endpoint** at `https://oidc-bridge.aitc.dev`. It uses the
admin token populated in Phase 10 Task 15 Step 4.

The result: the bridge knows about sdk-example as a registered app with a
specific `client_id`, the production sdk-example domain in the `Origin`
allowlist, and the production Supabase third-party-OIDC redirect / id_token
audience configured.

- [ ] **Step 1: Create the workspace + app**

```bash
ADMIN_TOKEN="$(gcloud secrets versions access latest \
  --secret=oidc-bridge-admin-token \
  --project=apps-in-toss-community-prod)"

# Create the workspace.
pnpm bridge --base https://oidc-bridge.aitc.dev workspace create \
  --name "Apps In Toss Community" \
  --display-id "aitc"

# Output looks like:
#   workspace created: ws_abc123 ("Apps In Toss Community")

# Create the app inside that workspace.
pnpm bridge --base https://oidc-bridge.aitc.dev app create \
  --workspace ws_abc123 \
  --display-name "sdk-example" \
  --toss-app-id "<sdk-example-toss-mini-app-id>" \
  --client-type public \
  --origin https://sdk-example.aitc.dev

# Output:
#   app created: client_id=app_abcdef123456
#   public client (Origin allowlist mode)
#   origins: ["https://sdk-example.aitc.dev"]
```

Save the resulting `client_id` — sdk-example needs it as `VITE_BRIDGE_CLIENT_ID`.

- [ ] **Step 2: Upload mTLS material**

```bash
# Toss-issued mTLS cert + key for the sdk-example mini-app live on the
# operator's local filesystem in `~/Toss/sdk-example.{cert,key}.pem`.
pnpm bridge --base https://oidc-bridge.aitc.dev app set-mtls \
  --client-id app_abcdef123456 \
  --cert-file ~/Toss/sdk-example.cert.pem \
  --key-file  ~/Toss/sdk-example.key.pem

# Output:
#   mTLS material stored (encrypted at rest, sealing_key_version=1)
```

Verify it doesn't return:

```bash
pnpm bridge --base https://oidc-bridge.aitc.dev app show \
  --client-id app_abcdef123456 \
  --json | jq 'keys'
```

Expected: the JSON keys array contains `client_id`, `display_name`, `toss_app_id`, `client_type`, `origins`, `created_at`, `mtls_present`, but NOT `mtls_cert_pem` or `mtls_key_pem` (Phase 4 invariant).

- [ ] **Step 3: Add a "production app registration" entry to `docs/LAUNCH.md` (created in Task 2 below)**

Defer to Task 2 — `LAUNCH.md` doesn't exist yet.

- [ ] **Step 4: Smoke the new app**

```bash
# Sanity: discovery URL returns the issuer matching what Supabase will see.
curl -fsS https://oidc-bridge.aitc.dev/.well-known/openid-configuration | jq .issuer
# Expected: "https://oidc-bridge.aitc.dev"

# JWKS has at least one key.
curl -fsS https://oidc-bridge.aitc.dev/.well-known/jwks.json | jq '.keys | length'
# Expected: >= 1

# /oidc/token rejects missing client_id with invalid_request.
curl -fsS -X POST https://oidc-bridge.aitc.dev/oidc/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data 'grant_type=authorization_code' \
  -w '\n%{http_code}\n' || true
# Expected: HTTP 400 with body {"error":"invalid_request",...}
```

This task does not produce a code change to commit. It produces operational state — the production bridge knows about sdk-example. Capture the `client_id` and the operator command sequence in `docs/LAUNCH.md` (Task 2).

---

## Task 2 (`oidc-bridge` repo): `docs/LAUNCH.md` (M5 launch checklist)

**Files:**
- Create: `docs/LAUNCH.md`
- Modify: `docs/RUNBOOK.md`

- [ ] **Step 1: Write `docs/LAUNCH.md`**

```markdown
# M5 launch — public instance + sdk-example dog-fooding

This document captures the M5 launch checklist for the public oidc-bridge
instance at `https://oidc-bridge.aitc.dev`. The launch gate is a green
end-to-end run from a deployed sdk-example: `appLogin()` → bridge → Supabase
session.

## Pre-launch checklist

- [ ] Phase 9 complete: self-host artifacts + image smoke green on `main`.
- [ ] Phase 10 complete: public bridge serving on `https://oidc-bridge.aitc.dev`.
      Verify with `curl -fsS https://oidc-bridge.aitc.dev/healthz` returning `ok`.
- [ ] Master-key v1 bytes populated in GCPSM. Verify with
      `gcloud secrets versions list oidc-bridge-master-key-v1` showing at least
      one ENABLED version that is NOT the sentinel.
- [ ] Admin token stored in GCPSM and in operator password manager.
- [ ] sdk-example workspace + app registered on the production bridge:
      ```bash
      pnpm bridge --base https://oidc-bridge.aitc.dev workspace create \
        --name "Apps In Toss Community" --display-id "aitc"
      pnpm bridge --base https://oidc-bridge.aitc.dev app create \
        --workspace <ws_id> --display-name "sdk-example" \
        --toss-app-id "<toss-mini-app-id>" --client-type public \
        --origin https://sdk-example.aitc.dev
      pnpm bridge --base https://oidc-bridge.aitc.dev app set-mtls \
        --client-id <client_id> \
        --cert-file <path> --key-file <path>
      ```
- [ ] sdk-example deployed at `https://sdk-example.aitc.dev` with the new
      `AuthPage` (Phase 11 sdk-example PR merged).
- [ ] Supabase project's auth → providers → third-party-OIDC has
      `https://oidc-bridge.aitc.dev` registered with audience matching
      `<client_id>`.

## Launch verification

Run, in order:

1. `BRIDGE_PROD_E2E=1 pnpm e2e:prod` from this repo. Expected: all Playwright
   tests pass.
2. Open `https://sdk-example.aitc.dev/auth` in the Toss mini-app shell. Sign
   in with a Toss test account. Expected: lands in the post-login screen,
   Supabase JWT is in the page state.
3. Click "show me Toss claims". Expected: a panel renders with `userKey`,
   `scope`, `agreedTerms` fields, and the encrypted PII fields are shown
   as opaque base64 (not decoded).
4. Force a token refresh by waiting for id_token expiry (1h) or by clearing
   `sessionStorage.id_token`. Expected: page silently re-authenticates via
   the bridge `refresh_token` grant.

If all four pass: M5 is launched.

## Post-launch ops

- The nightly Playwright cron (`.github/workflows/prod-e2e.yml`) runs the
  full E2E daily at 03:00 KST. A failure pages whoever is on call.
- `pnpm bridge doctor --base https://oidc-bridge.aitc.dev --json | jq .status`
  runs from cron weekly; alerting fires on red.
- Master-key rotation (Phase 1 design) is a quarterly task: see
  [`PUBLIC_INSTANCE.md`](./PUBLIC_INSTANCE.md) → "Master-key rotation".

## Rollback

If launch verification fails:

1. **sdk-example side:** revert the sdk-example PR. The legacy `AuthPage`
   no longer works (Phase 4 removed `POST /verify`), so reverting puts users
   into a broken state — only do this if the bridge side is also rolled back.
2. **Bridge side:** roll back to the previous Cloud Run revision via the
   `Promote/rollback Cloud Run revision` workflow (`.github/workflows/deploy-prod.yml`).
   `gh workflow run deploy-prod.yml -f revision_tag=rev-<previous> -f reason="..."`.

The rollback chain is documented in [`PUBLIC_INSTANCE.md`](./PUBLIC_INSTANCE.md);
this file just points at it.
```

- [ ] **Step 2: Append a pointer in `docs/RUNBOOK.md`**

After the section added in Phase 10 Task 13, append:

```markdown

## M5 launch verification

The launch checklist and the day-of-launch verification flow are in
[`LAUNCH.md`](./LAUNCH.md). The nightly Playwright cron at
`.github/workflows/prod-e2e.yml` keeps the same flow green continuously
post-launch.
```

- [ ] **Step 3: Commit**

```bash
git add docs/LAUNCH.md docs/RUNBOOK.md
git commit -m "docs: M5 launch checklist (LAUNCH.md) + RUNBOOK pointer"
```

---

## Task 3 (`sdk-example` repo): PKCE helpers

**Files (in sdk-example):**
- Create: `src/auth/pkce.ts`
- Create: `src/auth/pkce.test.ts`

PKCE is optional in the bridge (decision #9), but using it strengthens the
public-client mode. Two pure functions: `generateVerifier()` returns a
high-entropy random string base64url-encoded; `deriveChallenge(verifier)`
returns SHA-256(verifier) base64url-encoded.

- [ ] **Step 1: Write the failing test**

```ts
// src/auth/pkce.test.ts
import { describe, expect, it } from 'vitest';
import { deriveChallenge, generateVerifier } from './pkce.ts';

describe('PKCE', () => {
  it('generateVerifier returns a base64url string of >=43 chars', () => {
    const v = generateVerifier();
    expect(v).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
  });

  it('two calls return different verifiers', () => {
    const a = generateVerifier();
    const b = generateVerifier();
    expect(a).not.toBe(b);
  });

  it('deriveChallenge(verifier) returns SHA-256 base64url-encoded (43 chars, no padding)', async () => {
    const v = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST'; // 46 chars, RFC 7636 lower bound is 43
    const c = await deriveChallenge(v);
    expect(c).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Determinism.
    expect(await deriveChallenge(v)).toBe(c);
  });

  it('deriveChallenge differs across verifiers', async () => {
    const a = await deriveChallenge('verifier-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    const b = await deriveChallenge('verifier-two-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(a).not.toBe(b);
  });
});
```

- [ ] **Step 2: Run, confirm it fails**

```bash
pnpm test src/auth/pkce.test.ts 2>&1 | tail -10
```

Expected: 4 failing (file does not exist).

- [ ] **Step 3: Implement**

```ts
// src/auth/pkce.ts
function base64UrlEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function generateVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function deriveChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}
```

- [ ] **Step 4: Run, confirm it passes**

```bash
pnpm test src/auth/pkce.test.ts 2>&1 | tail -10
```

Expected: 4 passed.

- [ ] **Step 5: Commit (in sdk-example)**

```bash
git add src/auth/pkce.ts src/auth/pkce.test.ts
git commit -m "feat: PKCE verifier + challenge helpers (S256, base64url, no padding)"
```

---

## Task 4 (`sdk-example` repo): `bridge-client.ts` — `/oidc/token` exchange

**Files (in sdk-example):**
- Create: `src/auth/bridge-client.ts`
- Create: `src/auth/bridge-client.test.ts`

The client has three operations:
1. `exchangeAuthCode({ authorizationCode, codeVerifier })` → token-set.
2. `refresh({ refreshToken })` → token-set.
3. `userinfo({ accessToken })` → userinfo JSON.

A "token-set" = `{ id_token, access_token, refresh_token, expires_in, scope }`.

- [ ] **Step 1: Write failing tests (msw mocks for /oidc/token)**

```ts
// src/auth/bridge-client.test.ts
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { createBridgeClient } from './bridge-client.ts';

const server = setupServer();

beforeEach(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());

const BASE = 'https://bridge.test';
const CLIENT_ID = 'app_test123';

describe('bridge-client', () => {
  it('exchangeAuthCode posts form-encoded grant_type=authorization_code', async () => {
    let captured: { contentType: string | null; body: string } | null = null;
    server.use(
      http.post(`${BASE}/oidc/token`, async ({ request }) => {
        captured = {
          contentType: request.headers.get('content-type'),
          body: await request.text(),
        };
        return HttpResponse.json({
          id_token: 'eyJhbGciOiJSUzI1NiJ9.fake.fake',
          access_token: 'ait_aaaaaaaa',
          refresh_token: 'ait_bbbbbbbb',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'openid profile',
        });
      }),
    );

    const client = createBridgeClient({ baseUrl: BASE, clientId: CLIENT_ID });
    const tokens = await client.exchangeAuthCode({
      authorizationCode: 'toss-code-xyz',
      codeVerifier: 'pkce-verifier-123',
    });

    expect(captured?.contentType).toBe('application/x-www-form-urlencoded');
    const params = new URLSearchParams(captured!.body);
    expect(params.get('grant_type')).toBe('authorization_code');
    expect(params.get('code')).toBe('toss-code-xyz');
    expect(params.get('client_id')).toBe(CLIENT_ID);
    expect(params.get('code_verifier')).toBe('pkce-verifier-123');
    expect(params.get('client_secret')).toBeNull();

    expect(tokens.id_token).toMatch(/^eyJ/);
    expect(tokens.access_token).toBe('ait_aaaaaaaa');
    expect(tokens.refresh_token).toBe('ait_bbbbbbbb');
    expect(tokens.expires_in).toBe(3600);
  });

  it('exchangeAuthCode surfaces invalid_grant errors with description', async () => {
    server.use(
      http.post(`${BASE}/oidc/token`, () =>
        HttpResponse.json(
          {
            error: 'invalid_grant',
            error_description: 'authorization code expired',
          },
          { status: 400 },
        ),
      ),
    );
    const client = createBridgeClient({ baseUrl: BASE, clientId: CLIENT_ID });
    await expect(
      client.exchangeAuthCode({ authorizationCode: 'expired', codeVerifier: 'v' }),
    ).rejects.toMatchObject({
      error: 'invalid_grant',
      error_description: 'authorization code expired',
    });
  });

  it('refresh posts grant_type=refresh_token', async () => {
    let body: string | null = null;
    server.use(
      http.post(`${BASE}/oidc/token`, async ({ request }) => {
        body = await request.text();
        return HttpResponse.json({
          id_token: 'eyJhbGciOiJSUzI1NiJ9.fresh.fresh',
          access_token: 'ait_cccc',
          refresh_token: 'ait_dddd',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'openid',
        });
      }),
    );
    const client = createBridgeClient({ baseUrl: BASE, clientId: CLIENT_ID });
    const tokens = await client.refresh({ refreshToken: 'ait_old' });
    const params = new URLSearchParams(body!);
    expect(params.get('grant_type')).toBe('refresh_token');
    expect(params.get('refresh_token')).toBe('ait_old');
    expect(params.get('client_id')).toBe(CLIENT_ID);
    expect(tokens.access_token).toBe('ait_cccc');
  });

  it('userinfo sends Authorization: Bearer ait_<...>', async () => {
    let auth: string | null = null;
    server.use(
      http.get(`${BASE}/oidc/userinfo`, ({ request }) => {
        auth = request.headers.get('authorization');
        return HttpResponse.json({
          sub: '1234567',
          provider: 'toss',
          'toss:userKey': 1234567,
          'toss:agreedTerms': ['terms-of-service-v1'],
          scope: 'openid profile',
        });
      }),
    );
    const client = createBridgeClient({ baseUrl: BASE, clientId: CLIENT_ID });
    const info = await client.userinfo({ accessToken: 'ait_xyz' });
    expect(auth).toBe('Bearer ait_xyz');
    expect(info.sub).toBe('1234567');
    expect(info['toss:userKey']).toBe(1234567);
  });

  it('userinfo never logs the token to console', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    server.use(
      http.get(`${BASE}/oidc/userinfo`, () =>
        HttpResponse.json({ sub: 'u1', provider: 'toss' }),
      ),
    );
    const client = createBridgeClient({ baseUrl: BASE, clientId: CLIENT_ID });
    await client.userinfo({ accessToken: 'ait_secret_should_not_appear' });
    for (const call of consoleSpy.mock.calls) {
      const joined = JSON.stringify(call);
      expect(joined).not.toMatch(/ait_secret_should_not_appear/);
      expect(joined).not.toMatch(/Bearer/);
    }
    consoleSpy.mockRestore();
  });
});
```

- [ ] **Step 2: Run, confirm failures**

```bash
pnpm test src/auth/bridge-client.test.ts 2>&1 | tail -10
```

Expected: 5 failing (`bridge-client.ts` does not exist).

- [ ] **Step 3: Implement**

```ts
// src/auth/bridge-client.ts
export interface TokenSet {
  id_token: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: 'Bearer';
  scope: string;
}

export interface UserInfo {
  sub: string;
  provider: string;
  scope?: string;
  [key: string]: unknown; // Toss-prefixed fields, encrypted PII fields
}

export interface BridgeClientOptions {
  baseUrl: string;
  clientId: string;
  /** Override fetch for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export interface BridgeError extends Error {
  error: string;
  error_description?: string;
  status: number;
}

function makeError(status: number, body: { error?: string; error_description?: string }): BridgeError {
  const error = body.error ?? 'unknown_error';
  const description = body.error_description ?? `bridge returned HTTP ${status}`;
  const e = new Error(`${error}: ${description}`) as BridgeError;
  e.error = error;
  e.error_description = body.error_description;
  e.status = status;
  return e;
}

export function createBridgeClient(opts: BridgeClientOptions) {
  const fetchImpl = opts.fetchImpl ?? fetch;

  async function postToken(params: URLSearchParams): Promise<TokenSet> {
    const r = await fetchImpl(`${opts.baseUrl}/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
    });
    const text = await r.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw makeError(r.status, { error: 'invalid_response', error_description: text.slice(0, 200) });
    }
    if (!r.ok) {
      throw makeError(r.status, body as { error?: string; error_description?: string });
    }
    return body as TokenSet;
  }

  return {
    async exchangeAuthCode(input: {
      authorizationCode: string;
      codeVerifier: string;
    }): Promise<TokenSet> {
      const params = new URLSearchParams();
      params.set('grant_type', 'authorization_code');
      params.set('code', input.authorizationCode);
      params.set('client_id', opts.clientId);
      params.set('code_verifier', input.codeVerifier);
      return postToken(params);
    },

    async refresh(input: { refreshToken: string }): Promise<TokenSet> {
      const params = new URLSearchParams();
      params.set('grant_type', 'refresh_token');
      params.set('refresh_token', input.refreshToken);
      params.set('client_id', opts.clientId);
      return postToken(params);
    },

    async userinfo(input: { accessToken: string }): Promise<UserInfo> {
      const r = await fetchImpl(`${opts.baseUrl}/oidc/userinfo`, {
        headers: { authorization: `Bearer ${input.accessToken}` },
      });
      if (!r.ok) {
        const text = await r.text();
        let body: { error?: string; error_description?: string } = {};
        try {
          body = JSON.parse(text);
        } catch {
          body = { error: 'invalid_response', error_description: text.slice(0, 200) };
        }
        throw makeError(r.status, body);
      }
      return (await r.json()) as UserInfo;
    },
  };
}
```

- [ ] **Step 4: Run, confirm it passes**

```bash
pnpm test src/auth/bridge-client.test.ts 2>&1 | tail -10
```

Expected: 5 passed.

- [ ] **Step 5: Commit (in sdk-example)**

```bash
git add src/auth/bridge-client.ts src/auth/bridge-client.test.ts
git commit -m "feat: bridge-client (token exchange, refresh, userinfo)"
```

---

## Task 5 (`sdk-example` repo): Supabase third-party-OIDC wiring

**Files (in sdk-example):**
- Modify: `src/lib/supabase.ts`
- Modify: `.env.example`

`src/lib/supabase.ts` already creates the Supabase client. Add a typed
helper `signInWithBridgeIdToken(idToken)` that calls
`supabase.auth.signInWithIdToken({ provider: 'toss', token: idToken })`
and returns the resulting session, or throws a structured error.

- [ ] **Step 1: Add the helper**

```ts
// src/lib/supabase.ts
import { createClient, type Session } from '@supabase/supabase-js';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  throw new Error(
    'VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY are required. ' +
      'Set them in .env.local; see .env.example.',
  );
}

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export interface SupabaseSignInError extends Error {
  cause?: unknown;
}

/**
 * Signs in to Supabase using a bridge-issued id_token. Returns the resulting
 * session. Throws if Supabase rejects the token (typically a third-party-OIDC
 * config mismatch).
 */
export async function signInWithBridgeIdToken(idToken: string): Promise<Session> {
  const { data, error } = await supabase.auth.signInWithIdToken({
    provider: 'toss',
    token: idToken,
  });
  if (error) {
    const e = new Error(
      `Supabase rejected the id_token: ${error.message}. ` +
        'Check that the bridge issuer is configured as a third-party OIDC provider in Supabase.',
    ) as SupabaseSignInError;
    e.cause = error;
    throw e;
  }
  if (!data.session) {
    throw new Error('Supabase signInWithIdToken returned no session');
  }
  return data.session;
}
```

- [ ] **Step 2: Update `.env.example`**

```bash
# .env.example (sdk-example)

# --- Supabase ---
VITE_SUPABASE_URL=https://<project>.supabase.co
VITE_SUPABASE_ANON_KEY=<anon key from Supabase dashboard>

# --- Bridge ---
# Default points at the community public instance. Self-hosters override.
VITE_BRIDGE_URL=https://oidc-bridge.aitc.dev
# Obtained from `pnpm bridge app create` against the bridge admin.
VITE_BRIDGE_CLIENT_ID=app_<your-client-id>
```

- [ ] **Step 3: Type-check**

```bash
pnpm typecheck 2>&1 | tail -5
```

Expected: 0 errors.

- [ ] **Step 4: Commit (in sdk-example)**

```bash
git add src/lib/supabase.ts .env.example
git commit -m "feat: signInWithBridgeIdToken helper; .env.example with bridge vars"
```

---

## Task 6 (`sdk-example` repo): `AuthPage.tsx` rewrite

**Files (in sdk-example):**
- Modify: `src/auth/AuthPage.tsx` (REPLACE)
- Create: `src/auth/AuthPage.test.tsx`

The page state machine has four states: `idle` → `signing-in` → `signed-in` | `error`.

The login button calls `appLogin()` from `@apps-in-toss/web-framework`, then
`bridgeClient.exchangeAuthCode`, then `signInWithBridgeIdToken`, then renders
the post-login view. On error at any step, render the error.

- [ ] **Step 1: Write the failing test (msw + react-testing-library)**

```tsx
// src/auth/AuthPage.test.tsx
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthPage } from './AuthPage.tsx';

const server = setupServer();

vi.mock('@apps-in-toss/web-framework', () => ({
  appLogin: vi.fn(async () => ({
    authorizationCode: 'toss-code-mock',
    referrer: 'mini-app://test',
  })),
}));
vi.mock('../lib/supabase.ts', () => ({
  signInWithBridgeIdToken: vi.fn(async () => ({
    access_token: 'sb_jwt',
    user: { id: 'u-1', email: null },
  })),
}));

beforeAll(() => {
  // jsdom doesn't have crypto.subtle.digest by default in some setups; provide a polyfill if needed.
  if (!globalThis.crypto.subtle) {
    // @ts-expect-error -- test polyfill
    globalThis.crypto = require('node:crypto').webcrypto;
  }
  // Allow tests to inject env via Vite's import.meta.env shim.
  // @ts-expect-error -- test setup
  import.meta.env = {
    VITE_BRIDGE_URL: 'https://bridge.test',
    VITE_BRIDGE_CLIENT_ID: 'app_test',
    VITE_SUPABASE_URL: 'https://supa.test',
    VITE_SUPABASE_ANON_KEY: 'anon',
  };
});

beforeEach(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());

describe('AuthPage', () => {
  it('renders the Login button at idle', () => {
    render(<AuthPage />);
    expect(screen.getByRole('button', { name: /login with toss/i })).toBeInTheDocument();
  });

  it('happy path: appLogin → /oidc/token → signInWithIdToken → signed-in', async () => {
    server.use(
      http.post('https://bridge.test/oidc/token', () =>
        HttpResponse.json({
          id_token: 'eyJhbGciOiJSUzI1NiJ9.id.tok',
          access_token: 'ait_at',
          refresh_token: 'ait_rt',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'openid',
        }),
      ),
    );
    render(<AuthPage />);
    fireEvent.click(screen.getByRole('button', { name: /login with toss/i }));
    await waitFor(() => expect(screen.getByText(/signed in/i)).toBeInTheDocument());
    // Sealed AT is in sessionStorage for re-auth.
    expect(window.sessionStorage.getItem('ait_access_token')).toBe('ait_at');
    expect(window.sessionStorage.getItem('ait_refresh_token')).toBe('ait_rt');
    // Refresh token is sealed shape, not JWT shape.
    expect(window.sessionStorage.getItem('ait_refresh_token')).toMatch(/^ait_/);
    expect(window.sessionStorage.getItem('ait_refresh_token')).not.toMatch(/^eyJ/);
  });

  it('error path: bridge returns invalid_grant; user-visible error rendered', async () => {
    server.use(
      http.post('https://bridge.test/oidc/token', () =>
        HttpResponse.json(
          { error: 'invalid_grant', error_description: 'code expired' },
          { status: 400 },
        ),
      ),
    );
    render(<AuthPage />);
    fireEvent.click(screen.getByRole('button', { name: /login with toss/i }));
    await waitFor(() =>
      expect(screen.getByText(/code expired/i)).toBeInTheDocument(),
    );
    // No fall-through to anonymous auth.
    expect(window.sessionStorage.getItem('ait_access_token')).toBeNull();
  });
});
```

- [ ] **Step 2: Run, confirm failures**

```bash
pnpm test src/auth/AuthPage.test.tsx 2>&1 | tail -10
```

Expected: 3 failing (`AuthPage.tsx` does not yet have the new shape).

- [ ] **Step 3: Implement `AuthPage.tsx`**

```tsx
// src/auth/AuthPage.tsx
import { useState } from 'react';
import { appLogin } from '@apps-in-toss/web-framework';
import { createBridgeClient } from './bridge-client.ts';
import { deriveChallenge, generateVerifier } from './pkce.ts';
import { signInWithBridgeIdToken } from '../lib/supabase.ts';
import { TossClaimsButton } from './TossClaimsButton.tsx';

type State =
  | { kind: 'idle' }
  | { kind: 'signing-in' }
  | { kind: 'signed-in'; sealedAccessToken: string }
  | { kind: 'error'; message: string };

const BRIDGE_URL = import.meta.env.VITE_BRIDGE_URL;
const CLIENT_ID = import.meta.env.VITE_BRIDGE_CLIENT_ID;

if (!BRIDGE_URL || !CLIENT_ID) {
  throw new Error(
    'VITE_BRIDGE_URL and VITE_BRIDGE_CLIENT_ID are required. See .env.example.',
  );
}

const bridgeClient = createBridgeClient({ baseUrl: BRIDGE_URL, clientId: CLIENT_ID });

export function AuthPage() {
  const [state, setState] = useState<State>({ kind: 'idle' });

  async function handleLogin(): Promise<void> {
    setState({ kind: 'signing-in' });
    try {
      const verifier = generateVerifier();
      // The bridge does not require us to bind the challenge in /oidc/token call shape
      // beyond sending code_verifier; for stricter PKCE flows we'd send code_challenge
      // on a /authorize step (which this bridge does not have, decision #4).
      // We compute the challenge for parity with future PKCE-strict deployments.
      void (await deriveChallenge(verifier));

      const { authorizationCode } = await appLogin();
      const tokens = await bridgeClient.exchangeAuthCode({
        authorizationCode,
        codeVerifier: verifier,
      });

      window.sessionStorage.setItem('ait_access_token', tokens.access_token);
      window.sessionStorage.setItem('ait_refresh_token', tokens.refresh_token);

      await signInWithBridgeIdToken(tokens.id_token);

      setState({ kind: 'signed-in', sealedAccessToken: tokens.access_token });
    } catch (e) {
      const message =
        e && typeof e === 'object' && 'error_description' in e
          ? String((e as { error_description: unknown }).error_description)
          : e instanceof Error
            ? e.message
            : 'Unknown error';
      setState({ kind: 'error', message });
    }
  }

  if (state.kind === 'signed-in') {
    return (
      <div data-testid="signed-in">
        <p>Signed in.</p>
        <TossClaimsButton sealedAccessToken={state.sealedAccessToken} />
      </div>
    );
  }

  return (
    <div>
      <button type="button" onClick={handleLogin} disabled={state.kind === 'signing-in'}>
        {state.kind === 'signing-in' ? 'Signing in…' : 'Login with Toss'}
      </button>
      {state.kind === 'error' ? (
        <p role="alert" style={{ color: 'red' }}>
          {state.message}
        </p>
      ) : null}
    </div>
  );
}
```

- [ ] **Step 4: Run, confirm it passes**

```bash
pnpm test src/auth/AuthPage.test.tsx 2>&1 | tail -10
```

Expected: 3 passed.

- [ ] **Step 5: Commit (in sdk-example)**

```bash
git add src/auth/AuthPage.tsx src/auth/AuthPage.test.tsx
git commit -m "feat: AuthPage rewrite (appLogin -> bridge -> Supabase, no /verify)"
```

---

## Task 7 (`sdk-example` repo): `TossClaimsButton.tsx` ("show me Toss claims")

**Files (in sdk-example):**
- Create: `src/auth/TossClaimsButton.tsx`
- Create: `src/auth/TossClaimsButton.test.tsx`

When clicked, calls `bridgeClient.userinfo`, renders the result inline. The
button is bound at handler-time; nothing fires on mount (invariant 3).

- [ ] **Step 1: Failing test**

```tsx
// src/auth/TossClaimsButton.test.tsx
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { TossClaimsButton } from './TossClaimsButton.tsx';

const server = setupServer();

beforeAll(() => {
  // @ts-expect-error -- test setup
  import.meta.env = {
    VITE_BRIDGE_URL: 'https://bridge.test',
    VITE_BRIDGE_CLIENT_ID: 'app_test',
  };
});
beforeEach(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());

describe('TossClaimsButton', () => {
  it('does not call /oidc/userinfo on mount', () => {
    let calls = 0;
    server.use(
      http.get('https://bridge.test/oidc/userinfo', () => {
        calls++;
        return HttpResponse.json({ sub: 'u' });
      }),
    );
    render(<TossClaimsButton sealedAccessToken="ait_x" />);
    expect(calls).toBe(0);
  });

  it('shows claims after click', async () => {
    server.use(
      http.get('https://bridge.test/oidc/userinfo', () =>
        HttpResponse.json({
          sub: '1234567',
          provider: 'toss',
          'toss:userKey': 1234567,
          'toss:agreedTerms': ['terms-of-service-v1'],
          scope: 'openid profile',
        }),
      ),
    );
    render(<TossClaimsButton sealedAccessToken="ait_x" />);
    fireEvent.click(screen.getByRole('button', { name: /show me toss claims/i }));
    await waitFor(() => expect(screen.getByText(/userKey/)).toBeInTheDocument());
    expect(screen.getByText(/1234567/)).toBeInTheDocument();
    expect(screen.getByText(/terms-of-service-v1/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run, confirm failures**

```bash
pnpm test src/auth/TossClaimsButton.test.tsx 2>&1 | tail -10
```

Expected: 2 failing.

- [ ] **Step 3: Implement**

```tsx
// src/auth/TossClaimsButton.tsx
import { useState } from 'react';
import { createBridgeClient, type UserInfo } from './bridge-client.ts';

const BRIDGE_URL = import.meta.env.VITE_BRIDGE_URL;
const CLIENT_ID = import.meta.env.VITE_BRIDGE_CLIENT_ID;
const bridgeClient = createBridgeClient({ baseUrl: BRIDGE_URL, clientId: CLIENT_ID });

interface Props {
  sealedAccessToken: string;
}

export function TossClaimsButton({ sealedAccessToken }: Props) {
  const [state, setState] = useState<
    | { kind: 'idle' }
    | { kind: 'loading' }
    | { kind: 'loaded'; info: UserInfo }
    | { kind: 'error'; message: string }
  >({ kind: 'idle' });

  async function handleClick(): Promise<void> {
    setState({ kind: 'loading' });
    try {
      const info = await bridgeClient.userinfo({ accessToken: sealedAccessToken });
      setState({ kind: 'loaded', info });
    } catch (e) {
      const message =
        e && typeof e === 'object' && 'error_description' in e
          ? String((e as { error_description: unknown }).error_description)
          : e instanceof Error
            ? e.message
            : 'Unknown error';
      setState({ kind: 'error', message });
    }
  }

  return (
    <div>
      <button type="button" onClick={handleClick} disabled={state.kind === 'loading'}>
        {state.kind === 'loading' ? 'Loading…' : 'Show me Toss claims'}
      </button>
      {state.kind === 'loaded' ? (
        <pre data-testid="toss-claims" style={{ whiteSpace: 'pre-wrap' }}>
          {JSON.stringify(state.info, null, 2)}
        </pre>
      ) : null}
      {state.kind === 'error' ? (
        <p role="alert" style={{ color: 'red' }}>
          {state.message}
        </p>
      ) : null}
    </div>
  );
}
```

- [ ] **Step 4: Run, confirm it passes**

```bash
pnpm test src/auth/TossClaimsButton.test.tsx 2>&1 | tail -10
```

Expected: 2 passed.

- [ ] **Step 5: Commit (in sdk-example)**

```bash
git add src/auth/TossClaimsButton.tsx src/auth/TossClaimsButton.test.tsx
git commit -m "feat: TossClaimsButton (lazy /oidc/userinfo, on-click only)"
```

---

## Task 8 (`sdk-example` repo): README + Supabase third-party-OIDC config

**Files (in sdk-example):**
- Modify: `README.md`

This is documentation + an operator instruction for Supabase. Code-wise,
the work is done; the README needs to reflect the new auth flow and tell
readers how to register the bridge as a Supabase third-party-OIDC provider.

- [ ] **Step 1: Replace the README "Authentication" section**

Find the existing "Authentication" / "Login" section in sdk-example's README
(it currently describes `POST /verify`) and replace with:

```markdown
## Authentication (zero-code mode via the community oidc-bridge)

sdk-example signs users in by calling Toss `appLogin()`, exchanging the
returned authorization code at `https://oidc-bridge.aitc.dev` for an
RS256-signed id_token, and handing that id_token to Supabase via
`signInWithIdToken`. There is no custom backend; Supabase is the only
backend.

```
mini-app browser
   |  appLogin()                                    -> Toss
   |  POST /oidc/token (grant_type=authorization_code)  -> oidc-bridge
   |  signInWithIdToken({ provider: 'toss', token })    -> Supabase
   v
post-login screen
```

### Supabase third-party-OIDC setup

In your Supabase project:

1. Auth → Providers → Enable third-party-OIDC.
2. Add a provider with:
   - Issuer: `https://oidc-bridge.aitc.dev`
   - JWKS URL: `https://oidc-bridge.aitc.dev/.well-known/jwks.json`
     (Supabase auto-discovers this via `/.well-known/openid-configuration`.)
   - Audience: the `client_id` you got from
     `pnpm bridge app create --client-type public`.
   - Provider name: `toss` (must match `provider: 'toss'` in `signInWithIdToken`).

The bridge's id_token claims map to Supabase user metadata as follows:

| Claim                | Supabase field                              |
|----------------------|---------------------------------------------|
| `sub`                | `auth.users.id` (or external_id, per project) |
| `provider`           | `app_metadata.provider`                     |
| `toss:userKey`       | `user_metadata.toss_user_key`               |
| `toss:agreedTerms`   | `user_metadata.toss_agreed_terms`           |
| `iss`                | matches the configured issuer; required     |

### Local development

```bash
cp .env.example .env.local
# Edit .env.local: set VITE_SUPABASE_URL, VITE_SUPABASE_ANON_KEY,
# VITE_BRIDGE_URL (default https://oidc-bridge.aitc.dev), VITE_BRIDGE_CLIENT_ID.
pnpm dev
```

For self-hosted bridge: set `VITE_BRIDGE_URL=http://localhost:8080` and follow
[`oidc-bridge/docs/SELF_HOSTING.md`](https://github.com/apps-in-toss-community/oidc-bridge/blob/main/docs/SELF_HOSTING.md)
for the bootstrap flow.

### Showing Toss claims

The post-login screen has a "Show me Toss claims" button that calls
`/oidc/userinfo` with the sealed `ait_access_token`. The response is the
mapped userinfo document; encrypted PII fields appear opaque (as base64
strings) — the bridge does not hold the decryption key.
```

- [ ] **Step 2: Verify README link rendering**

```bash
# If sdk-example uses any README linter, run it. Otherwise just eyeball.
grep -nE 'POST /verify|/verify' README.md
```

Expected: zero matches in the README. The legacy endpoint name is gone.

- [ ] **Step 3: Commit (in sdk-example)**

```bash
git add README.md
git commit -m "docs: replace POST /verify auth section with bridge + Supabase flow"
```

---

## Task 9 (`sdk-example` repo): Open the sdk-example PR

- [ ] **Step 1: Open the PR**

Title: `Auth: replace POST /verify with oidc-bridge + Supabase`

Body (markdown):

```markdown
## Summary
- Remove the legacy `POST /verify` `AuthPage` flow (the bridge endpoint was
  removed in oidc-bridge#<phase-4-PR>).
- New `AuthPage` flow: `appLogin()` → `https://oidc-bridge.aitc.dev/oidc/token`
  → `supabase.auth.signInWithIdToken({ provider: 'toss' })`.
- New `TossClaimsButton` calls `/oidc/userinfo` with the sealed
  `ait_access_token` on click.
- Public-client mode: no `client_secret`, authentication via the bridge's
  CORS-validated `Origin` allowlist.
- PKCE (S256) verifier + challenge generated per session.
- Token-set persisted to `sessionStorage` (sealed; never JWT-shaped).
- README rewritten with Supabase third-party-OIDC setup instructions.

## Test plan
- [ ] `pnpm test` — all unit + component tests pass (PKCE, bridge-client,
      AuthPage, TossClaimsButton).
- [ ] `pnpm typecheck` — clean.
- [ ] `pnpm dev` — local Vite dev server boots, `/auth` route renders the
      Login button.
- [ ] Manual: in a real Toss mini-app shell, log in successfully against
      the staging `oidc-bridge` instance.
- [ ] Manual: click "Show me Toss claims" — expect a JSON dump including
      `toss:userKey`, `toss:agreedTerms`, encrypted PII opaque fields.
- [ ] No console.log lines contain `Bearer` or `ait_` or `eyJ` substrings
      (verified via the `userinfo never logs the token to console` unit test).

## Cross-repo dependency
This PR requires `oidc-bridge` Phase 10 (public instance live at
`https://oidc-bridge.aitc.dev`) and Phase 11 Tasks 1–2 (sdk-example app
registered on the production bridge admin). Do not merge before those land.
```

- [ ] **Step 2: Review handoff**

Two-stage review:
1. Spec compliance reviewer confirms the five-bullet scope statement from
   §11 Phase 11 is fully covered.
2. Code-quality reviewer confirms no `client_secret` in the public-client
   path, no console.log of secrets, no `waitForTimeout` in any spec.

---

## Task 10 (`oidc-bridge` repo): Production Playwright E2E spec

**Files:**
- Create: `playwright.config.ts`
- Create: `test/e2e/prod-mini-app.spec.ts`

This Playwright test runs against the deployed sdk-example. It does not
spawn a real Toss mini-app shell; instead, it authenticates a stored
`storageState` (an encrypted blob committed via git-crypt out-of-band),
navigates to `/auth`, clicks Login, waits for the post-login screen,
asserts the Supabase JWT is present, clicks "Show me Toss claims", and
asserts the userinfo render includes `toss:userKey`.

- [ ] **Step 1: Add Playwright as a devDependency**

```bash
pnpm add -D @playwright/test@latest
pnpm exec playwright install --with-deps chromium
```

- [ ] **Step 2: Write `playwright.config.ts`**

```ts
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './test/e2e',
  testMatch: /.*\.spec\.ts$/,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: process.env.SDK_EXAMPLE_URL ?? 'https://sdk-example.aitc.dev',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    storageState: process.env.PLAYWRIGHT_STORAGE_STATE,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
```

- [ ] **Step 3: Write the spec**

```ts
// test/e2e/prod-mini-app.spec.ts
import { expect, test } from '@playwright/test';

const ENABLED = process.env.BRIDGE_PROD_E2E === '1';

test.skip(!ENABLED, 'BRIDGE_PROD_E2E=1 not set');

test.describe('production sdk-example dog-food', () => {
  test('login flow round-trip + show me Toss claims', async ({ page }) => {
    // The page navigates to the auth route. Storage state was loaded by Playwright
    // config; cookies / localStorage carry a Toss session that allows appLogin()
    // to succeed without an interactive popup.
    await page.goto('/auth');

    await expect(page.getByRole('button', { name: /login with toss/i })).toBeVisible();

    // Wait for the bridge token call to complete after click.
    const tokenResp = page.waitForResponse(
      (r) => r.url().includes('/oidc/token') && r.request().method() === 'POST',
    );
    await page.getByRole('button', { name: /login with toss/i }).click();
    const tr = await tokenResp;
    expect(tr.status()).toBe(200);
    const tokenBody = await tr.json();
    expect(tokenBody).toHaveProperty('id_token');
    expect(tokenBody.access_token).toMatch(/^ait_/);
    expect(tokenBody.refresh_token).toMatch(/^ait_/);

    // Post-login screen.
    await expect(page.getByText(/signed in/i)).toBeVisible();

    // Sanity: sessionStorage carries sealed tokens, not JWTs.
    const sessionAt = await page.evaluate(() => window.sessionStorage.getItem('ait_access_token'));
    const sessionRt = await page.evaluate(() => window.sessionStorage.getItem('ait_refresh_token'));
    expect(sessionAt).toMatch(/^ait_/);
    expect(sessionRt).toMatch(/^ait_/);
    expect(sessionAt).not.toMatch(/^eyJ/);
    expect(sessionRt).not.toMatch(/^eyJ/);

    // Click "Show me Toss claims".
    const userinfoResp = page.waitForResponse((r) => r.url().includes('/oidc/userinfo'));
    await page.getByRole('button', { name: /show me toss claims/i }).click();
    const ur = await userinfoResp;
    expect(ur.status()).toBe(200);
    const ui = await ur.json();
    expect(ui).toHaveProperty('toss:userKey');
    expect(typeof ui['toss:userKey']).toBe('number');
    // The userinfo response must NOT echo mTLS material (defensive).
    expect(ui).not.toHaveProperty('mtls_cert_pem');
    expect(ui).not.toHaveProperty('mtls_key_pem');
    expect(ui).not.toHaveProperty('client_secret');
  });
});
```

- [ ] **Step 4: Add `e2e:prod` script to `package.json`**

```json
"e2e:prod": "BRIDGE_PROD_E2E=1 playwright test test/e2e/prod-mini-app.spec.ts",
"e2e:prod:headed": "BRIDGE_PROD_E2E=1 playwright test test/e2e/prod-mini-app.spec.ts --headed"
```

- [ ] **Step 5: Verify config + skip-on-default**

```bash
pnpm exec playwright test --reporter=list 2>&1 | tail -10
```

Expected: 1 test, skipped (because `BRIDGE_PROD_E2E` is unset).

Run with the gate on (requires `PLAYWRIGHT_STORAGE_STATE` to be a valid storage-state file with a logged-in Toss session):

```bash
BRIDGE_PROD_E2E=1 PLAYWRIGHT_STORAGE_STATE=./.playwright-state/toss.json pnpm e2e:prod
```

Expected: 1 test, passed. (This step requires operator setup; if storage-state is not yet captured, document the `playwright codegen` flow in `docs/LAUNCH.md` per Task 2.)

- [ ] **Step 6: Commit**

```bash
git add playwright.config.ts test/e2e/prod-mini-app.spec.ts package.json pnpm-lock.yaml
git commit -m "test: production sdk-example E2E (Playwright, gated by BRIDGE_PROD_E2E)"
```

---

## Task 11 (`oidc-bridge` repo): Nightly cron workflow

**Files:**
- Create: `.github/workflows/prod-e2e.yml`

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/prod-e2e.yml
name: prod-e2e

on:
  schedule:
    # 03:00 KST = 18:00 UTC.
    - cron: '0 18 * * *'
  workflow_dispatch: {}

permissions:
  contents: read

jobs:
  e2e:
    name: Production E2E
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with: { version: '10.33.0' }

      - uses: actions/setup-node@v4
        with:
          node-version: '24'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile

      - name: Install Playwright browsers
        run: pnpm exec playwright install --with-deps chromium

      - name: Materialize storage state
        env:
          PLAYWRIGHT_STORAGE_STATE_B64: ${{ secrets.PLAYWRIGHT_STORAGE_STATE_B64 }}
        run: |
          mkdir -p .playwright-state
          echo "$PLAYWRIGHT_STORAGE_STATE_B64" | base64 -d > .playwright-state/toss.json
          chmod 600 .playwright-state/toss.json

      - name: Run E2E
        env:
          BRIDGE_PROD_E2E: '1'
          PLAYWRIGHT_STORAGE_STATE: .playwright-state/toss.json
          SDK_EXAMPLE_URL: https://sdk-example.aitc.dev
        run: pnpm e2e:prod

      - name: Upload Playwright artifacts on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report
          path: |
            playwright-report/
            test-results/
          retention-days: 14
```

- [ ] **Step 2: Configure secret out-of-band**

```bash
# Capture a fresh storage-state once via codegen (interactive):
pnpm exec playwright codegen https://sdk-example.aitc.dev/auth \
  --save-storage=./.playwright-state/toss.json

# Then push to GitHub secrets:
gh secret set PLAYWRIGHT_STORAGE_STATE_B64 \
  --body "$(base64 -i ./.playwright-state/toss.json)"
```

This is one-shot operator work; it is documented in `docs/LAUNCH.md`.

- [ ] **Step 3: Validate workflow syntax**

```bash
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest -color
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/prod-e2e.yml
git commit -m "ci: nightly prod-e2e cron (03:00 KST) running Playwright spec"
```

---

## Task 12 (`oidc-bridge` repo): Open the bridge-side PR

- [ ] **Step 1: Open the PR**

Title: `Phase 11: M5 launch — sdk-example dog-fooding harness`

Body (markdown):

```markdown
## Summary
- Production app registered on the public bridge for sdk-example
  (workspace, app, mTLS material — operator commands captured in
  `docs/LAUNCH.md`).
- `docs/LAUNCH.md`: M5 launch checklist + post-launch ops + rollback.
- `playwright.config.ts` + `test/e2e/prod-mini-app.spec.ts`: production E2E
  spec gated by `BRIDGE_PROD_E2E=1`.
- `.github/workflows/prod-e2e.yml`: nightly cron at 03:00 KST that runs the
  spec against `https://sdk-example.aitc.dev` against the public bridge.
- `package.json`: `e2e:prod` + `e2e:prod:headed` scripts.

## Test plan
- [ ] `pnpm install --frozen-lockfile` succeeds.
- [ ] `pnpm exec playwright install --with-deps chromium` succeeds.
- [ ] `pnpm e2e:prod` skips by default (no `BRIDGE_PROD_E2E`).
- [ ] `BRIDGE_PROD_E2E=1 PLAYWRIGHT_STORAGE_STATE=... pnpm e2e:prod` passes
      against the production sdk-example.
- [ ] `actionlint .github/workflows/prod-e2e.yml` is clean.
- [ ] Cron workflow runs to green in its first scheduled invocation
      (verified manually via `gh workflow run prod-e2e.yml`).

## Cross-repo dependency
The sdk-example PR introducing the new auth flow must be deployed before
the cron will be green. Sequence: (1) merge this PR; (2) merge the
sdk-example PR; (3) deploy sdk-example; (4) trigger the cron manually to
verify.
```

- [ ] **Step 2: Review handoff**

Two-stage review:
1. Spec compliance reviewer confirms the launch gate is correctly wired
   (manual checklist + nightly cron + rollback procedure).
2. Code-quality reviewer confirms the cron workflow does not log secret
   contents, the storage-state secret is base64-encoded (not raw JSON in
   the repo), and the Playwright spec uses `waitForResponse` rather than
   `waitForTimeout`.

---

## Task 13: M5 launch (operator action)

- [ ] **Step 1: Verify Phase 9 + Phase 10 are merged and green on `main`**

Check `main` branch CI is green; check `https://oidc-bridge.aitc.dev/healthz` returns `ok`.

- [ ] **Step 2: Merge the bridge Phase 11 PR (Task 12)**

The cron is configured but the storage-state secret may not be set yet; the cron will fail until Step 5 below. That's fine — the manual launch verification in Step 6 is what gates "launched".

- [ ] **Step 3: Merge the sdk-example PR (Task 9)**

Watch sdk-example's deploy pipeline. Once `https://sdk-example.aitc.dev/auth` shows the new "Login with Toss" button (and not the legacy `/verify` form), proceed.

- [ ] **Step 4: Configure Supabase third-party-OIDC**

In Supabase: Auth → Providers → enable third-party-OIDC, register the bridge issuer with the sdk-example `client_id` as audience. Verify by signing in with a test Toss account end-to-end.

- [ ] **Step 5: Capture and upload Playwright storage-state**

```bash
pnpm exec playwright codegen https://sdk-example.aitc.dev/auth \
  --save-storage=./.playwright-state/toss.json
gh secret set PLAYWRIGHT_STORAGE_STATE_B64 \
  --body "$(base64 -i ./.playwright-state/toss.json)"
```

- [ ] **Step 6: Run the launch verification flow from `docs/LAUNCH.md`**

Run all four steps under "Launch verification". If all pass: M5 is launched.

- [ ] **Step 7: Trigger the nightly cron once manually to confirm it works**

```bash
gh workflow run prod-e2e.yml
gh run watch "$(gh run list --workflow=prod-e2e.yml --limit=1 --json databaseId --jq '.[0].databaseId')"
```

Expected: green within 10 minutes. From here, the cron runs nightly without intervention.

---

## Done condition

Phase 11, and therefore the M5 launch milestone, is done when:

1. `https://sdk-example.aitc.dev/auth` shows the new "Login with Toss"
   button (no `POST /verify` path remains in the deployed sdk-example).
2. A real Toss test account can complete the full login flow:
   `appLogin()` → `/oidc/token` → `signInWithIdToken` → post-login screen
   → "Show me Toss claims" → userinfo render with `toss:userKey`.
3. The sealed `ait_refresh_token` survives a forced id_token refresh
   (clearing `sessionStorage.id_token`) and produces a new Supabase
   session without re-prompting the user.
4. The nightly cron at `.github/workflows/prod-e2e.yml` has run green
   at least once.
5. `docs/LAUNCH.md` "Launch verification" all four steps pass.
6. The Phase 11 sdk-example PR and the Phase 11 oidc-bridge PR are both
   merged with both reviewers' approval.
7. The landing-page README (`apps-in-toss-community.github.io/content/`)
   notes the public bridge as launched (a small, separate edit done by
   the operator after this phase closes — not part of this plan).

That state is the M5 launch gate. From this point forward, the bridge
is "launched" and the project moves to M6 (sdk-example auth demo
polish + additional IdP scenarios), which is out of scope here.

This is the final phase of the zero-code mode rollout. Subsequent
work (M6, multi-region, Cloud Run revisioning improvements, additional
BaaS providers) follows under separate plans.
