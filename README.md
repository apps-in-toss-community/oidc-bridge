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
  ghcr.io/apps-in-toss-community/oidc-bridge:latest
```

`/healthz` → `200 ok`. Service listens on `PORT` (default `8080`, Cloud Run convention). See [Environment](#environment) for the full set of knobs (most are planned and currently ignored — the scaffold only reads `PORT`).

### Environment

The current build only reads `PORT`. All other knobs below are **planned**; they are listed here so self-hosters can wire them up ahead of the M1-M4 milestones (see [`TODO.md`](./TODO.md)).

| Var | Required | Status | Purpose |
|---|---|---|---|
| `PORT` | no | current | Listen port (default `8080`) |
| `TOSS_CLIENT_ID` | yes (M1) | planned | Toss partner client ID |
| `TOSS_CLIENT_SECRET` | yes (M1) | planned | Toss partner client secret |
| `TOSS_API_BASE` | no | planned | Override upstream (default `https://apps-in-toss-api.toss.im`) |
| `FIREBASE_SERVICE_ACCOUNT` | optional | planned (M2) | Raw JSON (or base64). Required for `/firebase-token` |
| `GOOGLE_APPLICATION_CREDENTIALS` | optional | planned (M2) | Alternative: path to the JSON service account |
| `OIDC_SIGNING_KEY` | optional | planned (M4) | PEM-encoded RSA/EC private key, for the OIDC provider surface |
| `OIDC_ISSUER` | optional | planned (M4) | Issuer URL that OIDC consumers will whitelist |
| `TOSS_PII_DECRYPTION_KEY` | optional | planned | If set, bridge can decrypt Toss `/login-me` PII fields on explicit opt-in |
| `ALLOWED_ORIGINS` | optional | planned (M3) | Comma-separated CORS allow-list |
| `RATE_LIMIT_ENABLED` | optional | planned (M3) | `true` on the public image, defaults `false` for self-host |

Secrets are never logged. `.env` supported in dev.

## API

| Endpoint | Status |
|---|---|
| `POST /verify` | **current** — returns `501 not_implemented` until real Toss token verification lands |
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

Response (once implemented):

```json
{
  "sub": "<stable user id>",
  "provider": "toss",
  "claims": { "userKey": "...", "scopes": ["user_key", "user_name"] },
  "tossAccessTokenExpiresAt": 1746300000
}
```

Errors follow OAuth 2.0 / OIDC conventions: `{ "error": "...", "error_description": "..." }` with `400 invalid_request`, `401 invalid_code`, `429 rate_limited`, `502 upstream_error`.

## License

BSD-3-Clause.

## Status

Pre-stable scaffold: `POST /verify` is a 501 stub, `/firebase-token` and the OIDC provider surface are planned. See [`TODO.md`](./TODO.md) for the remaining work and [`CLAUDE.md`](./CLAUDE.md) § 마일스톤 for the repo-level milestone view. The [organization landing page](https://apps-in-toss-community.github.io/) has the cross-repo roadmap.
