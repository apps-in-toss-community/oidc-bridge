# CLAUDE.md

## 프로젝트 성격

비공식(unofficial) 커뮤니티 프로젝트. 사용자에게 보이는 산출물에서 "공식/official/powered by Toss" 등 제휴·인증 암시 표현 금지. 공용 인스턴스는 **rate-limited, best-effort, community-operated**. 상세는 umbrella `../CLAUDE.md`의 "프로젝트 성격" 참조.

## 짝 repo

- **`sdk-example`** — bridge M5 launch gate가 여기로 묶인다. sdk-example의 `AuthPage`가 옛 `POST /verify`를 버리고 Supabase Edge Function (`supabase/functions/toss-login`)으로 `/oidc/token` → `signInWithIdToken` 경로를 만든다. 이 Edge Function이 README와 `agent-plugin` 템플릿의 canonical reference.
- **`agent-plugin`** — `/ait new` auth 옵션이 이 bridge를 가리킨다.

다른 repo와의 전체 짝 그림은 umbrella `../CLAUDE.md`의 "짝(pair) 관계" 참조. 기본적으로 **독립 서비스** — launch만 sdk-example dog-fooding에 묶인다.

## 프로젝트 개요

**oidc-bridge** — 토스 로그인을 표준 OIDC 어댑터로 중계해서 mini-app 운영자가 Supabase / Firebase / Auth0 / Keycloak 같은 일반 IdP 통합 흐름으로 토스 로그인을 붙일 수 있게 해주는 multi-tenant 서버.

전체 설계는 [`docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md`](docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md). 본 문서와 충돌하면 spec이 source of truth.

### 왜 필요한가

토스는 OIDC IdP가 아니다 — `/authorize`, JWKS, `state`/PKCE 같은 OIDC 프리미티브가 없고, partner API는 mTLS만 받는다. Supabase Edge Functions(Deno Deploy)와 Firebase Cloud Functions에서는 outbound mTLS가 어렵거나 비포팅이고, **Firebase Spark 플랜은 Cloud Functions의 outbound 외부 호출 자체를 막는다**. Bridge는 그래서 단순 편의가 아니라 integration path 그 자체.

### 운영 모델

- **공용 인스턴스** (`oidc-bridge.aitc.dev`, SLA 없음) — Vultr Cloud Compute Seoul 단일 VPS + Docker + Caddy. ~$5/mo (`vc2-1c-1gb`).
- **Self-host** — 동일 Docker 이미지 + 동일 `docker-compose.yml`. `RATE_LIMIT_ENABLED=false` 기본. Spark 플랜에서 Firebase Custom Token을 원하면 self-host가 유일한 길.

보안이 민감한 production 사용자는 self-host 권장.

## 아키텍처

### Multi-tenant + 거의 stateless

Tenant store만이 유일한 영속 상태 — (mTLS cert+key, OIDC `client_id`, `client_secret` hash, 메타데이터). 그 외에는 stateless: 세션 스토어/DB/Redis 없음. Bridge가 발급하는 access_token은 **sealed wrapper** — `(tenant_id, toss_AT, toss_RT, exp)`을 per-tenant 키로 AEAD(AES-256-GCM)로 봉인한 opaque string (`aitc_<base64url>`). Rate-limit 카운터는 in-memory per-instance (M3).

배포 산출물: 단일 Docker 이미지 (`node:24-alpine`, multi-stage). entrypoint `node dist/server.mjs`, `PORT` default `8080`, `/healthz` → `200 ok`. 공용 인스턴스는 Vultr VPS의 docker-compose + Caddy(TLS 종단).

### Tenant store 백엔드

`TENANT_STORE=fs|gcpsm` env로 선택. `fs`는 `${BRIDGE_DATA_DIR}/tenants/${id}.json` (perm 600, self-host default). `gcpsm`은 Google Secret Manager `oidc-bridge-tenant-${id}` + clientId 인덱스 (공용 인스턴스 default, lazy import).

### `/oidc/token`이 foundational primitive

모든 데이터 경로(`/oidc/userinfo`, `/oidc/revoke`, M2 `/firebase-token`)가 sealed access_token unwrap → tenant lookup → mTLS Toss 호출 한 군데에 수렴한다. 새 endpoint 추가 시 이 구조 유지.

### Framework: Hono

Runtime-agnostic + 작은 표면 + 빠른 cold-start + CORS/rate-limit/JWT verify 미들웨어 제공. `@hono/node-server`로 Node 24 위에서 돌리되 Workers 배포 옵션은 미래에도 열려있다. **Fastify/Express 거부** — edge/runtime 이식성과 cold start 때문.

### API 표면 (M1 + M2)

모든 응답 JSON. 에러는 OAuth 2.0/OIDC 관례대로 `{ error, error_description }`.

- **OIDC (M1)**: `GET /.well-known/openid-configuration` (`authorization_endpoint`/`response_types_supported`는 의도적 omit — Toss SDK가 OIDC redirect 미지원), `GET /.well-known/jwks.json`, `POST /oidc/token` (`authorization_code`/`refresh_token`, 클라이언트 인증 = `client_secret_basic` | `client_secret_post`), `GET /oidc/userinfo` (Bearer → mTLS `/login-me`), `POST /oidc/revoke` (RFC 7009, 항상 200).
- **Admin (M1)**: `POST/GET/PATCH/DELETE /admin/tenants` + `POST /admin/tenants/:id/secrets/rotate`, `ADMIN_TOKEN` bearer로 보호.
- **CLI (M1)**: 번들로 동봉. Admin REST의 thin client + self-host bootstrap 모드(로컬 config에 직접 쓰기).
- **Firebase (M2, self-host only)**: `POST /firebase-token` — `firebase-admin`으로 Firebase Custom Token 서명. `FIREBASE_SERVICE_ACCOUNT` 없으면 `501 not_configured`. 공용 인스턴스는 항상 501.
- **Liveness**: `GET /healthz`.

## Toss adapter

### 흐름

1. Mini-app `appLogin()` → `{ authorizationCode, referrer }` (10분).
2. Consumer 백엔드 → Bridge `POST /oidc/token`.
3. Bridge: tenant lookup → tenant mTLS cert+key로 `https.Agent` 구성.
4. POST `https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss/user/oauth2/generate-token` (mTLS), body `{ authorizationCode, referrer }`.
5. 응답 envelope `{ resultType: "SUCCESS"|"FAIL", success?, error? }` — flat 형태 아님. 어댑터의 `envelope.ts` 한 군데에서만 다룬다.
6. `success`: `accessToken` (RS256 JWT, kid="cert", iss="cert.toss.im"), `refreshToken`, `expiresIn`, `scope`.
7. 같은 mTLS 채널로 `/oauth2/login-me` → `userKey`, `scope`, `agreedTerms`, 암호화된 PII.
8. ID token 서명 + sealed access_token 발급 → 표준 OAuth2 응답.

### 인증

mTLS only (`TLS_CLIENT_CERT` + `TLS_CLIENT_KEY` per tenant, PEM). 토스 콘솔에서 발급, 390일 유효, 무제한, sandbox/production 단일 cert. HTTP Basic / X-Client-Id 같은 옛 scaffold 가정은 폐기.

### Toss AT 서명 검증?

**하지 않는다.** Toss는 JWKS를 퍼블리시하지 않고 partner-side 서명 검증을 문서화하지 않는다. 문서가 명시하는 검증 신호는 `/login-me` 성공 그 자체. Bridge는 AT를 opaque로 취급하고 모든 outbound claim은 mTLS + bearer로 인증된 `/login-me` 응답에서만 가져온다. 시스템의 property이지 추적되는 gap이 아니다.

### Claim 매핑

`sub` = `/login-me` `userKey` (string-cast, 세션 간 안정), `iss` = `OIDC_ISSUER` env, `aud` = `client_id` (= tenant_id), `iat`/`exp`/`nbf` = bridge clock (id_token TTL = 1h, Toss AT와 정렬), `provider` = `"toss"`, `scope` = Toss-returned scope (space-joined), `toss:userKey` = 숫자(type 보존), `toss:agreedTerms` = string array, `toss:tossAccessTokenExpiresAt` = unix seconds.

PII 필드(name/phone/birthday/CI/gender/nationality)는 Toss-encrypted opaque 그대로 passthrough. Bridge는 PII decryption key를 보관하지 않는다.

## 모듈 구조 (M1)

```
src/
  app.ts, server.ts, config.ts, errors.ts
  oidc/    # discovery, jwks, token, userinfo, revoke, sealed-token, id-token, client-auth
  toss/    # client (mTLS Agent), generate-token, refresh-token, login-me, access-remove, envelope, types
  tenants/ # store interface, fs-store, gcpsm-store, types
  admin/   # routes, auth (ADMIN_TOKEN bearer)
  firebase/ # M2: custom-token, routes
cli/index.ts + cli/commands/{tenant-create,list,show,rotate-secret,delete}.ts
```

## Secrets 처리

### Tenant secrets (per-tenant)

mTLS cert + key (PEM)는 tenant store에 암호화 저장 (GCPSM 자체 암호화, fs는 perm 600). `client_secret`은 bcrypt hash 배열만 저장. 평문은 발급/회전 시 한 번만 노출, **회전 overlap 지원**.

### Bridge global secrets (env)

- `OIDC_ISSUER` — discovery에 노출되는 issuer URL.
- `OIDC_SIGNING_KEY` — RSA-2048 PEM. `/jwks.json`에 공개키 노출.
- `OIDC_MASTER_KEY` — base64 32 bytes. Per-tenant sealing key를 HKDF로 유도. 공용 인스턴스는 GCPSM `oidc-bridge-master-key`에서 lazy load.
- `ADMIN_TOKEN` — Admin REST bearer.
- `TENANT_STORE` — `fs` | `gcpsm`. `BRIDGE_DATA_DIR` — fs store 루트.
- `TOSS_API_BASE` — default `https://apps-in-toss-api.toss.im`.

### Firebase service account (self-host 전용, M2)

`FIREBASE_SERVICE_ACCOUNT` (raw JSON 또는 base64) 또는 `GOOGLE_APPLICATION_CREDENTIALS` (JSON 경로). Lazy init, 없으면 `501 not_configured`. **공용 인스턴스는 end-user Firebase service account를 보관하지 않는다.**

### 로딩 관례

모든 secret은 env 또는 tenant store. dev는 `dotenv/config`. **로그 금지** — 구조화 logger가 알려진 secret 키 이름을 redact.

## Rate-limit / 남용 방지 (M3)

M1 범위 밖. M3에서: per-IP sliding-window 카운터(in-memory per instance), `ALLOWED_ORIGINS` env로 CORS allow-list, `/oidc/*` payload 8 KiB cap, 구조화 JSON 로그(PII 없음, `x-request-id` correlation).

## MCP 전략

**공용 MCP는 제공하지 않는다.** `oidc-bridge`의 기능은 전부 표준 OIDC HTTP로 노출되므로 에이전트가 `WebFetch`/`Bash`로 바로 호출 가능. 관리자 전용 remote MCP는 ops introspection용으로 고려하되 HTTP API + OpenTelemetry 구축 후. 판별 기준은 umbrella `../meta/mcp-strategy.md` 참조.

## 기술 스택 (repo-specific)

TypeScript ESM strict / **Hono** (+ `@hono/node-server`) / **jose** (ID token sign+verify, JWKS) / **bcryptjs** (client_secret hash) / **@google-cloud/secret-manager** (lazy) / **firebase-admin** (M2, lazy) / **commander** (또는 citty) for CLI / **node:crypto** + **node:tls** (AEAD, HKDF, mTLS Agent) / **tsdown** 빌드 / **vitest** 테스트.

조직 공통 스택(Node 24, pnpm 10.33.0, Biome lint+format, pre-commit hook 등)은 umbrella `../CLAUDE.md`의 "공통 스택" 참조.

## 명령어

```bash
pnpm dev         # watch
pnpm build       # tsdown
pnpm start       # node dist/server.mjs (배포 런타임 진입점)
pnpm typecheck   # tsc --noEmit
pnpm test        # vitest run
pnpm lint        # biome check .
```

전체 스크립트는 `package.json` 참조.

## 테스트 전략

- **Unit (vitest)**: sealing wrap/unwrap roundtrip + tamper rejection, ID token sign+verify, client auth (Basic + Post + bcrypt rotation overlap), Toss envelope parsing, claim 매핑.
- **Integration (Hono `app.request()`, no network)**: `/oidc/token` happy + invalid_client + invalid_grant, `/oidc/userinfo` happy + bad bearer, `/oidc/revoke` always-200, discovery+JWKS shape consistency, Admin CRUD with/without token.
- **mTLS**: `https.Agent` 빌드 indirect assertion. 실 핸드셰이크는 `pnpm test:e2e:live` (수동, sandbox cert 필요, CI 아님).
- **Contract fixtures**: `src/__fixtures__/`에 redacted `/generate-token` + `/login-me` SUCCESS/FAIL 응답.
- **CLI**: `--help` smoke + create-then-list against in-process Bridge.

## 릴리즈 정책

**Type C (서비스 repo)**. main push = 배포. **Changesets 미사용**, Docker 이미지 tag가 버전 역할. 공용 인스턴스: main push → `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>` → SSH로 Vultr Seoul VPS에 `docker compose pull && up -d` (`.github/workflows/deploy.yml`). 상세 셋업은 [`docs/DEPLOY.md`](./docs/DEPLOY.md). Self-host는 동일 이미지를 자기 인프라에 (`RATE_LIMIT_ENABLED=false` 기본). 의미 있는 마일스톤은 GitHub Release 수동.

조직 전체 release 정책 매트릭스는 umbrella `../CLAUDE.md` 및 `../meta/release-strategy.md` 참조.

## TODO

조직 단일 source는 umbrella `../TODO.md`. 이 repo의 `TODO.md`는 umbrella를 가리키는 stub.

## 마일스톤

| # | 내용 | 상태 |
|---|---|---|
| M0 / M0.5 | scaffold + 임시 `/verify` (Basic Auth) | 완료, M1으로 폐기 예정 |
| **M1** | **Multi-tenant OIDC + mTLS proxy** — tenant store, Admin REST + CLI, OIDC token/userinfo/revoke + discovery + JWKS, sealed AT, mTLS Toss adapter | **진행 중** |
| M2 | `/firebase-token` (self-host) + `firebase-admin` lazy init | next |
| M3 | Rate-limit + CORS + payload cap + 구조화 로깅 | next |
| M4 | (Optional) 헬퍼 mini-app 기반 `/authorize` redirect 흐름 | demand 봐서 |
| **M5** | **공용 인스턴스 launch** — Vultr Seoul 배포 + DNS + founding tenant + sdk-example dog-fooding (Supabase Edge Function으로 `AuthPage` 재구축, 공용 bridge로 Supabase 세션 E2E). dog-fooding 성공이 launch gate. | M1 후 |
| M6 | sdk-example auth 데모 polish + 추가 IdP 시나리오 | M5 이후 |

M1은 breaking change — 기존 `/verify`는 같은 릴리즈에서 제거되고 self-host 운영자에게 `MIGRATION.md`가 제공된다.

## Status

현재 main: `POST /verify` 가동 (임시 Basic Auth). M1 redesign이 다중 tenant + mTLS + OIDC surface로 전환한다. 전체 로드맵은 [landing page](https://apps-in-toss-community.github.io/) 참고.
