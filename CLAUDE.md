# CLAUDE.md

## 프로젝트 성격 (중요)

**`apps-in-toss-community`는 비공식(unofficial) 오픈소스 커뮤니티다.** 토스 팀과 제휴 없음. 사용자에게 보이는 산출물에서 "공식/official/토스가 제공하는/powered by Toss" 등 제휴·후원·인증 암시 표현을 **쓰지 않는다**. 대신 "커뮤니티/오픈소스/비공식"을 사용한다. 의심스러우면 빼라.

특히 공용 인스턴스를 운영할 때 **rate-limited, best-effort, community-operated**임을 명시. production용 보증 없음.

## 짝 repo

- **`sdk-example`** (downstream consumer) — oidc-bridge가 완성되면 sdk-example의 auth 섹션이 실제 토스 로그인 → Supabase/Firebase 세션까지의 **E2E 흐름을 데모**한다. 이게 bridge의 주요 품질 게이트.
- **`agent-plugin`** — `/ait new`에서 auth 옵션으로 Supabase/Firebase/Auth0를 선택하면 이 bridge를 가리키는 설정을 템플릿에 주입.

기본적으로 **독립 서비스**. 다른 repo 변경 없이 배포 가능.

## 프로젝트 개요

**oidc-bridge** — 토스 로그인을 표준 OIDC 어댑터로 중계해서, mini-app 운영자가 **Supabase / Firebase / Auth0 / Keycloak** 같은 일반 IdP 통합 흐름으로 토스 로그인을 붙일 수 있게 해주는 multi-tenant 서버.

전체 설계는 [`docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md`](docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md). 본 문서는 운영·코딩 컨벤션 요약본이며, 설계와 충돌하면 spec이 source of truth.

### 왜 필요한가

토스는 OIDC IdP가 아니다 — `/authorize`, JWKS, `state`/PKCE 같은 OIDC 프리미티브가 없고, partner API는 mTLS만 받는다. 게다가:

- **Supabase Edge Functions**(Deno Deploy)와 **Firebase Cloud Functions**에서 outbound mTLS는 어렵거나 비포팅.
- **Firebase Spark** 플랜은 Cloud Functions에서 Google 외부로 나가는 모든 outbound 호출을 막는다. 이게 critical — Spark 사용자에게는 토스 API로 직접 가는 길 자체가 없다.

따라서 bridge는 단순 편의 도구가 아니라 **integration path 그 자체**. mTLS를 종단하고, 표준 OIDC surface를 노출하고, self-host 사용자에게는 Firebase Custom Token도 직접 발급한다.

### 운영 모델

- **공용 인스턴스** (`oidc-bridge.aitc.dev`, rate-limited, best-effort, SLA 없음) — **Vultr Cloud Compute, Seoul (ICN) 리전**, 단일 VPS + Docker + Caddy(자동 HTTPS). 한국 리전 + IO-bound 워크로드 + ~$5/mo (`vc2-1c-1gb`) + self-hoster가 그대로 docker compose로 복제 가능해서 1순위.
- **Self-host** (Docker/Fly.io/k8s/임의 Docker host) — 동일 Docker 이미지 + 동일 `docker-compose.yml`. `RATE_LIMIT_ENABLED=false` 기본. Spark 플랜에서 Firebase Custom Token을 원하면 self-host가 유일한 길.

보안이 민감한 production 사용자는 self-host를 권장.

## 아키텍처

### Multi-tenant + 거의 stateless

- **Tenant** = (mTLS cert + key, OIDC `client_id`, OIDC `client_secret` hash, 메타데이터). Tenant store만이 유일한 영속 상태.
- 그 외에는 stateless: 세션 스토어 / DB / Redis 없음. 요청 간 서버 상태 없음.
- Bridge가 발급하는 access_token은 **sealed wrapper** — `(tenant_id, toss_AT, toss_RT, exp)`을 per-tenant 키로 AEAD(AES-256-GCM) 암호화한 opaque string (`aitc_<base64url>`). 별도 세션 저장소 없이 stateless 유지.
- Rate-limit 카운터는 in-memory per-instance (M3에서 합류).
- 배포 산출물: 단일 Docker 이미지 (`node:24-alpine`, multi-stage). entrypoint `node dist/server.mjs`, `PORT` (default `8080`), `/healthz` → `200 ok`. 공용 인스턴스는 이 이미지를 Vultr VPS 위에서 docker-compose로 띄우고 Caddy가 TLS 종단을 담당한다.

### Tenant store 백엔드

- **Filesystem** — self-host default. `${BRIDGE_DATA_DIR}/tenants/${id}.json`, perm 600.
- **Google Secret Manager** — 공용 인스턴스 default. `oidc-bridge-tenant-${id}` secret + clientId 인덱스.

선택은 `TENANT_STORE=fs|gcpsm` env로. GCPSM 백엔드는 lazy import.

### `/oidc/token`이 foundational primitive

모든 데이터 경로(`/oidc/userinfo`, `/oidc/revoke`, M2 `/firebase-token`)가 sealed access_token을 unwrap → tenant lookup → mTLS Toss 호출 한 군데에 수렴한다. 새 endpoint를 추가할 때 이 구조를 깨뜨리지 말 것.

### Framework: Hono

**Hono** 선택. 이유:

- **Runtime-agnostic** (Node, Bun, Deno, Cloudflare Workers, Vercel 등). 공용 인스턴스는 Vultr Seoul VPS의 Node 24 위에서 돌리지만, self-hoster는 자기가 쓰는 무엇이든 올리고 싶어할 것.
- **작은 표면 + 빠른 cold-start** — VPS 재시작/배포 간 다운타임을 줄이는 데 유의미.
- **CORS / rate-limit / JWT verify 미들웨어 제공**.
- `@hono/node-server`로 Node 24(조직 스택) 위에서 바로 돌리되, Workers 배포 옵션은 미래에도 열려있음.

**Fastify / Express는 거부** — Node에서는 괜찮지만 edge/runtime 이식성이 떨어지고 cold start가 무겁다.

### API 표면 (M1 + M2)

모든 응답 JSON. 에러는 OAuth 2.0 / OIDC 관례대로 `{ error, error_description }`.

**OIDC surface (M1)**:
- `GET /.well-known/openid-configuration` — discovery doc. `authorization_endpoint`와 `response_types_supported`는 의도적 omit (Toss SDK가 OIDC redirect 미지원).
- `GET /.well-known/jwks.json` — ID token 서명 공개키.
- `POST /oidc/token` — `grant_type=authorization_code` (code = Toss `authorizationCode`) / `refresh_token`. 클라이언트 인증 = `client_secret_basic` | `client_secret_post`.
- `GET /oidc/userinfo` — Bearer 인증, sealed AT unwrap → `/login-me` over mTLS.
- `POST /oidc/revoke` — RFC 7009. Toss `/access/remove-by-access-token` 매핑. (RFC 7009 준수: 항상 200.)

**Admin (M1)**:
- `POST/GET/PATCH/DELETE /admin/tenants`, `POST /admin/tenants/:id/secrets/rotate`. `ADMIN_TOKEN` env bearer로 보호. 향후 console SPA가 위에 올라간다.

**CLI (M1)**:
- 번들로 동봉. Admin REST의 thin client. `tenant create/list/show/rotate-secret/delete`. self-host bootstrap 모드는 로컬 config 파일에 직접 쓴다 (Bridge 미기동 상태에서도 첫 tenant 생성 가능).

**Firebase (M2, self-host only)**:
- `POST /firebase-token` — Toss authorizationCode (또는 sealed bridge AT)을 받아 `firebase-admin`으로 Firebase Custom Token 서명. `FIREBASE_SERVICE_ACCOUNT` 없으면 `501 not_configured`. **공용 인스턴스는 항상 501** — end-user service account를 보관하지 않는 게 보안 정책.

**Liveness**:
- `GET /healthz`.

## Toss adapter

### 흐름

1. Mini-app `appLogin()` → `{ authorizationCode, referrer }` (10분 유효).
2. Consumer 백엔드 (Supabase Edge / Firebase Function / 등) → Bridge `POST /oidc/token`.
3. Bridge: tenant lookup → tenant mTLS cert+key로 `https.Agent` 구성.
4. POST `https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss/user/oauth2/generate-token` (mTLS), body `{ authorizationCode, referrer }`.
5. 응답 envelope: `{ resultType: "SUCCESS"|"FAIL", success?: {...}, error?: {...} }` — flat 형태 아님. 어댑터의 `envelope.ts` 한 군데에서만 다룬다.
6. `success` 분기: `accessToken` (RS256 JWT, kid="cert", iss="cert.toss.im"), `refreshToken`, `expiresIn`, `scope`.
7. 같은 mTLS 채널로 `/oauth2/login-me` 호출 → `userKey`, `scope`, `agreedTerms`, 암호화된 PII.
8. ID token 서명 + sealed access_token 발급 → 표준 OAuth2 응답.

### 인증

- **mTLS** (`TLS_CLIENT_CERT` + `TLS_CLIENT_KEY` per tenant, PEM). 콘솔 → mTLS 인증서 → +발급받기. 390일 유효, 무제한 발급, sandbox/production 단일 cert.
- HTTP Basic Auth / X-Client-Id 헤더 같은 스킴은 사용하지 않는다 (이전 scaffold 가정 폐기).

### Toss AT 서명 검증?

**하지 않는다.** Toss는 JWKS를 퍼블리시하지 않고, partner-side 서명 검증을 문서화하지 않는다. 문서가 명시하는 검증 신호는 `/login-me` 성공 그 자체. Bridge는 AT를 opaque로 취급하고, 모든 outbound claim은 mTLS + bearer로 인증된 `/login-me` 응답에서만 가져온다. 이건 시스템의 property이지 추적되는 gap이 아니다.

### Claim 매핑

| OIDC claim | Source |
|---|---|
| `sub` | `/login-me`의 `userKey` (string-cast, 세션 간 안정) |
| `iss` | `OIDC_ISSUER` env |
| `aud` | OIDC `client_id` (= tenant_id) |
| `iat`, `exp`, `nbf` | bridge clock (id_token TTL = 1h, Toss AT와 정렬) |
| `provider` | 상수 `"toss"` |
| `scope` | Toss-returned scope, space-joined |
| `toss:userKey` | 숫자 `userKey` (type 보존) |
| `toss:agreedTerms` | `/login-me`의 array of strings |
| `toss:tossAccessTokenExpiresAt` | unix seconds |

PII 필드(name/phone/birthday/CI/gender/nationality)는 Toss-encrypted opaque 그대로 통과만 시킨다 (passthrough only). Bridge는 PII decryption key를 보관하지 않는다.

## 모듈 구조 (M1)

```
src/
  app.ts                       // Hono app factory
  server.ts                    // entrypoint
  config.ts                    // env parsing, public/self-host 모드
  errors.ts                    // OAuth2/OIDC error envelope
  oidc/
    discovery.ts               // /.well-known/openid-configuration
    jwks.ts                    // /.well-known/jwks.json
    token.ts                   // POST /oidc/token
    userinfo.ts                // GET /oidc/userinfo
    revoke.ts                  // POST /oidc/revoke
    sealed-token.ts            // AEAD wrap/unwrap
    id-token.ts                // ID token sign/verify (jose)
    client-auth.ts             // client_secret_basic + client_secret_post
  toss/
    client.ts                  // mTLS https.Agent + fetch wrapper
    generate-token.ts
    refresh-token.ts
    login-me.ts
    access-remove.ts
    envelope.ts                // resultType envelope handling
    types.ts
  tenants/
    store.ts                   // TenantStore interface
    fs-store.ts                // filesystem 백엔드
    gcpsm-store.ts             // Google Secret Manager 백엔드
    types.ts
  admin/
    routes.ts                  // /admin/tenants CRUD
    auth.ts                    // ADMIN_TOKEN bearer 미들웨어
  firebase/                    // M2
    custom-token.ts
    routes.ts
cli/
  index.ts
  commands/
    tenant-create.ts
    tenant-list.ts
    tenant-show.ts
    tenant-rotate-secret.ts
    tenant-delete.ts
```

## Secrets 처리

### Tenant secrets (per-tenant)

- mTLS cert + key (PEM) — tenant store에 암호화 저장 (GCPSM은 자체 암호화, fs는 perm 600).
- `client_secret` — bcrypt hash 배열만 저장. 평문은 발급/회전 시 한 번만 노출, 회전 overlap 지원.

### Bridge global secrets (env)

- `OIDC_ISSUER` — discovery에 노출되는 issuer URL.
- `OIDC_SIGNING_KEY` — RSA-2048 PEM. `/jwks.json`에 공개키 노출.
- `OIDC_MASTER_KEY` — base64 32 bytes. Per-tenant sealing key를 HKDF로 유도. 공용 인스턴스에서는 GCPSM `oidc-bridge-master-key`에서 lazy load.
- `ADMIN_TOKEN` — Admin REST bearer.
- `TENANT_STORE` — `fs` | `gcpsm`.
- `BRIDGE_DATA_DIR` — fs store 루트.
- `TOSS_API_BASE` — default `https://apps-in-toss-api.toss.im`.

### Firebase service account (self-host 전용, M2)

- `FIREBASE_SERVICE_ACCOUNT` — raw JSON 또는 base64.
- `GOOGLE_APPLICATION_CREDENTIALS` — JSON 경로, 대안.
- Lazy init. 없으면 `/firebase-token` → `501 not_configured`.

**공용 인스턴스는 end-user Firebase service account를 보관하지 않는다.**

### 로딩 관례

- 모든 secret은 env var 또는 tenant store. dev는 `dotenv/config`.
- **로그 금지**. 구조화 logger가 알려진 secret 키 이름을 redact.

## Rate-limit / 남용 방지 (M3)

M1 범위 밖. M3에서 추가:
- per-IP sliding-window 카운터, in-memory per instance.
- `ALLOWED_ORIGINS` env로 CORS allow-list.
- `/oidc/*` payload 8 KiB cap.
- 구조화 JSON 로그, PII 없음, `x-request-id` correlation.

## MCP 전략

**공용 MCP는 제공하지 않는다.** 이유:

- 공용 remote MCP는 인증/레이트리밋/민감 데이터 노출 설계 비용이 큼 (umbrella `CLAUDE.md` MCP 판별 체크리스트 참고).
- `oidc-bridge`의 기능은 전부 표준 OIDC HTTP로 노출. 에이전트가 `WebFetch`/`Bash`로 바로 호출 가능.
- 관리자 전용 remote MCP는 ops introspection용으로 고려하되 HTTP API + OpenTelemetry를 먼저 구축한 뒤. M1 밖.

## 기술 스택

- **TypeScript** (ESM only, strict)
- **Hono** — HTTP framework (+ `@hono/node-server`)
- **jose** — ID token sign/verify, JWKS
- **bcryptjs** — client_secret hashing
- **@google-cloud/secret-manager** — GCPSM tenant store (lazy)
- **firebase-admin** — M2, lazy
- **commander** (또는 citty) — CLI
- **node:crypto** / **node:tls** — AEAD, HKDF, mTLS Agent (built-in)
- **tsdown** — 빌드
- **vitest** — 테스트
- **pnpm** — 패키지 매니저 (10.33.0)
- **Biome** — lint + formatter (조직 표준)

## 명령어

```bash
pnpm build       # tsdown
pnpm start       # node dist/server.mjs
pnpm dev         # watch
pnpm typecheck   # tsc --noEmit
pnpm test        # vitest run
pnpm lint        # biome check .
pnpm lint:fix    # biome check --write .
pnpm format      # biome format --write .
```

## 테스트 전략

- **Unit (vitest)**: sealing wrap/unwrap roundtrip + tamper rejection / ID token sign+verify / client auth (Basic + Post + bcrypt rotation overlap) / Toss envelope parsing / claim 매핑.
- **Integration (Hono `app.request()`, no network)**: `/oidc/token` happy + invalid_client + invalid_grant / `/oidc/userinfo` happy + bad bearer / `/oidc/revoke` always-200 / discovery + JWKS shape consistency / Admin CRUD with/without token.
- **mTLS**: `https.Agent`가 tenant PEM으로 빌드되는지 indirect assertion. 실 핸드셰이크는 `pnpm test:e2e:live` (수동, sandbox cert 필요, CI 아님).
- **Contract fixtures**: `src/__fixtures__/`에 redacted `/generate-token` + `/login-me` SUCCESS/FAIL 응답.
- **CLI**: `--help` smoke + create-then-list against in-process Bridge.

## 릴리즈 정책

- **Type C (서비스 repo).** main push = 배포.
- **Changesets 사용 안 함.** 버전 개념 없음. Docker 이미지 tag가 버전 역할.
- **공용 인스턴스**: main push → Docker 이미지 빌드 → `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>` → SSH로 Vultr Seoul VPS에 접속해 `docker compose pull && up -d` (`.github/workflows/deploy.yml`). 상세 셋업은 [`docs/DEPLOY.md`](./docs/DEPLOY.md).
- **Self-host**: 사용자가 동일 이미지를 자기 인프라에. `RATE_LIMIT_ENABLED=false` 기본.
- 의미 있는 마일스톤은 GitHub Release를 수동으로 남겨 self-host 사용자가 구독/핀할 수 있게.

## 마일스톤

| # | 내용 | 상태 |
|---|---|---|
| M0 | Hono scaffold + `/verify` 스텁 + Dockerfile + CI green | 완료 |
| M0.5 | 임시 `/verify` (Basic Auth 가정) — **M1 redesign으로 폐기 예정** | 완료 (현재 main의 상태) |
| **M1** | **Multi-tenant OIDC + mTLS proxy** (현재 작업): tenant store, Admin REST + CLI, OIDC token/userinfo/revoke + discovery + JWKS, sealed access_token, mTLS Toss adapter | **진행 중** |
| M2 | `/firebase-token` (self-host) + `firebase-admin` lazy init | next |
| M3 | Rate-limit + CORS + payload cap + 구조화 로깅 | next |
| M4 | (Optional) 헬퍼 mini-app 기반 `/authorize` redirect 흐름 | follow-on, demand 봐서 |
| M5 | Vultr Seoul 배포 workflow (docker-compose + Caddy + GHCR + SSH deploy) + 공용 인스턴스 launch (founding tenant 등록 + sdk-example dog-fooding) | 인프라 코드 완료, Dave 수동 셋업 + M1 완료 후 launch |
| M6 | `sdk-example` auth 데모를 공용 인스턴스에 연결 (M5의 dog-fooding 결과) | M5 이후 |

상세 M1 설계는 [`docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md`](docs/superpowers/specs/2026-04-30-oidc-bridge-m1-redesign-design.md). M1은 breaking change — 기존 `/verify`는 같은 릴리즈에서 제거되고 self-host 운영자에게는 `MIGRATION.md`가 제공된다.

## Status

현재 main: `POST /verify` 가동 (임시 Basic Auth 모델). M1 redesign이 진행 중이며 이 PR로 다중 tenant + mTLS + OIDC surface로 전환된다.

전체 로드맵은 [landing page](https://apps-in-toss-community.github.io/) 참고.
