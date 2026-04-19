# oidc-bridge

> 🚧 **Work in Progress** — not yet published.
> 아직 개발 중입니다. 릴리스 전입니다.

OIDC + Firebase Custom Token bridge for [Toss](https://toss.im/) login.

토스 로그인을 **표준 OIDC**와 **Firebase Custom Token**으로 중계하는 커뮤니티 서버.

> This is an **unofficial, community-maintained** project. Not affiliated with or endorsed by Toss or the Apps in Toss team.
> 이 프로젝트는 **비공식 커뮤니티 프로젝트**입니다. 토스/앱인토스 팀과 제휴 관계가 아닙니다.

## Goal / 목표

토스 로그인을 Supabase Auth, Firebase Auth, Auth0 등 **어느 IdP에도 바로 붙일 수 있도록** 표준 OIDC와 Firebase Custom Token으로 변환한다.

Bridges Toss login into **standard OIDC** and **Firebase Custom Tokens**, so you can plug it straight into Supabase Auth, Firebase Auth, Auth0, or any OIDC-compatible IdP.

Stateless HTTP service — no DB, no session store. Each request: Toss `authorizationCode` in → verified claims / token out.

## How it works

```
mini-app ──appLogin()──▶ authorizationCode
   │
   │ POST /verify  { authorizationCode, referrer }
   ▼
oidc-bridge ──▶ Toss /oauth2/generate-token ──▶ verified claims
   │
   ├─▶ /firebase-token  → Firebase Custom Token (signed by your service account)
   └─▶ OIDC provider surface → Supabase / Auth0 / Keycloak plug-in
```

`/verify` is the foundational primitive; `/firebase-token` and the OIDC provider surface are built on top of it.

## Public community instance

A community-operated instance is planned on **Google Cloud Run `asia-northeast3` (Seoul)**:

- **Rate-limited** (per-IP, default 60 req/min; counters are per-instance, reset on scale-to-zero)
- **Best-effort, no SLA, no uptime guarantee**
- **Community-operated** — NOT provided, sponsored, or endorsed by Toss or the Apps in Toss team
- Exposes `/verify` and the OIDC provider surface. Does **not** hold end-user Firebase service accounts — use self-host for `/firebase-token`.

Security-sensitive production workloads should **self-host** instead.

## Self-host quickstart

The same Docker image backs the public instance and self-hosts. Image (coming soon):

```
ghcr.io/apps-in-toss-community/oidc-bridge:latest
```

### Run

```bash
docker run --rm -p 8080:8080 \
  -e TOSS_CLIENT_ID=your-client-id \
  -e TOSS_CLIENT_SECRET=your-client-secret \
  ghcr.io/apps-in-toss-community/oidc-bridge:latest
```

`/healthz` → `200 ok`. Service listens on `PORT` (default `8080`, Cloud Run convention). See [Environment](#environment) for the full set of knobs.

### Environment

`POST /verify` is wired up against Toss's partner API. The other rows below are **planned** for later milestones (see [`TODO.md`](./TODO.md)); milestone tags (`M2`, `M3`, ...) indicate when each becomes active.

| Var | Required | Status | Purpose |
|---|---|---|---|
| `PORT` | — | current | Listen port (default `8080`) |
| `TOSS_CLIENT_ID` | yes | current | Toss partner client ID (sent as HTTP Basic Auth username to `/oauth2/generate-token`) |
| `TOSS_CLIENT_SECRET` | yes | current | Toss partner client secret (Basic Auth password) |
| `TOSS_API_BASE` | — | current | Override upstream (default `https://apps-in-toss-api.toss.im`) |
| `FIREBASE_SERVICE_ACCOUNT` | — | planned (M2) | Raw JSON (or base64). Will be required for `/firebase-token` |
| `GOOGLE_APPLICATION_CREDENTIALS` | — | planned (M2) | Alternative: path to the JSON service account |
| `OIDC_SIGNING_KEY` | — | planned (M4) | PEM-encoded RSA/EC private key, for the OIDC provider surface |
| `OIDC_ISSUER` | — | planned (M4) | Issuer URL that OIDC consumers will whitelist |
| `TOSS_PII_DECRYPTION_KEY` | — | planned | If set, bridge can decrypt Toss `/login-me` PII fields on explicit opt-in |
| `ALLOWED_ORIGINS` | — | planned (M3) | Comma-separated CORS allow-list |
| `RATE_LIMIT_ENABLED` | — | planned (M3) | `true` on the public image, defaults `false` for self-host |

Secrets are never logged. `.env` supported in dev.

## API

| Endpoint | Status |
|---|---|
| `POST /verify` | **current** — calls Toss `/oauth2/generate-token` and returns normalized claims |
| `POST /firebase-token` | planned (self-host; requires Firebase service account) |
| `GET /.well-known/openid-configuration` | planned |
| `GET /.well-known/jwks.json` | planned |
| `GET /authorize` / `POST /token` / `GET /userinfo` | planned |
| `GET /healthz` | current |

See [`TODO.md`](./TODO.md) for the remaining implementation work.

### `POST /verify` (shape)

Request — both fields required; `referrer` must be `"DEFAULT"` or `"SANDBOX"`:

```json
{ "authorizationCode": "auth_xxx", "referrer": "DEFAULT" }
```

Response:

```json
{
  "sub": "<stable user id>",
  "provider": "toss",
  "claims": { "userKey": "...", "scopes": ["user_key", "user_name"] },
  "tossAccessTokenExpiresAt": 1746300000
}
```

Errors follow OAuth 2.0 / OIDC conventions: `{ "error": "...", "error_description": "..." }` with `400 invalid_request`, `401 invalid_code`, `500 server_misconfigured` (env vars missing), `502 upstream_error` / `502 invalid_upstream_response`. `429 rate_limited` lands with the M3 rate-limit middleware.

> v0 decodes the Toss `accessToken` but does **not** cryptographically verify its signature — the `/oauth2/generate-token` call itself is the verification signal. This is a documented pre-stable gap; signature verification lands once Toss clarifies the JWKS / shared-secret path. See [`CLAUDE.md`](./CLAUDE.md) § Toss verification.

## License

BSD-3-Clause.

## Status

Pre-stable: `POST /verify` is live against Toss's partner API (without AT signature verification — see API section). `/firebase-token` and the OIDC provider surface are planned. See [`TODO.md`](./TODO.md) for the remaining work and [`CLAUDE.md`](./CLAUDE.md) § 마일스톤 for the repo-level milestone view. The [organization landing page](https://apps-in-toss-community.github.io/) has the cross-repo roadmap.
