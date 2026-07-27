# CLAUDE.md

## 프로젝트 성격

`apps-in-toss-community`는 토스/앱인토스 팀과 제휴 관계가 없는 커뮤니티 프로젝트다.

사용자에게 보이는 모든 산출물(README, UI 카피, 패키지 설명, 커밋/PR 메시지, 코드 주석 등)에서 다음 표현 **금지**:

- "공식(official)", "공식 도구/플러그인", "토스가 제공하는", "앱인토스에서 만든", "powered by Toss"
- 토스와의 제휴/후원/인증을 암시하는 모든 표현

대신 "커뮤니티(community)" 같은 자연스러운 표현. 의심스러우면 빼라.

**톤 가이드** (방어적 disclaimer 금지): README 푸터에 한 줄로 1회만 명시 — ko `README.md`는 `커뮤니티 오픈소스 프로젝트입니다.`, en `README.en.md`는 `Community open-source project.`. "제휴 아님" 같은 방어적 표현 대신 "커뮤니티 오픈소스" 정체성만 자연스럽게. 헤더 직후의 `>` blockquote 박스, ⚠️ 아이콘, 굵은 글씨, `unofficial`/`비공식` 같은 강한 라벨은 쓰지 않는다. 한 파일 안에서 영/한 병기 금지(다중 언어는 ko/en 별도 파일로 분리). 운영 단서(공용 인스턴스 `oidc-bridge.aitc.dev`는 rate-limited, best-effort, SLA 없음, security-sensitive workloads는 self-host 권장)는 disclaimer에 묶지 않고 README의 "Self-host" 섹션에 운영 정보로 둔다.

**README i18n**: `README.md`(한국어, GitHub default) + `README.en.md`(영어). 둘 다 상단 상호 link(`[한국어](./README.md)` / `[English](./README.en.md)`), 동등 정본 — 한 쪽 갱신 시 같은 PR에서 반대쪽도 갱신. 전체 i18n 정책은 메인테이너 internal 문서가 정본입니다.

이슈/제안은 GitHub Issues로.

## 짝 repo

기본적으로 **독립 서비스** — launch만 `sdk-example` dog-fooding에 묶인다.

- **`sdk-example`** — bridge M5 launch gate가 여기로 묶인다. sdk-example의 `AuthPage`가 옛 `POST /verify`를 버리고 Supabase Edge Function (`supabase/functions/toss-login`)으로 `/oidc/token` → `signInWithIdToken` 경로를 만든다. 이 Edge Function이 README와 `agent-plugin` 템플릿의 canonical reference.
- **`agent-plugin`** — `/ait new` auth 옵션이 이 bridge를 가리킨다.

## 프로젝트 개요

**oidc-bridge** — 토스 로그인을 표준 OIDC 어댑터로 중계해서 mini-app 운영자가 Supabase / Firebase / Auth0 / Keycloak 같은 일반 IdP 통합 흐름으로 토스 로그인을 붙일 수 있게 해주는 multi-tenant 서버.

전체 설계는 [`docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md`](docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) (zero-code mode). 12-phase 구현 인덱스는 [`docs/superpowers/plans/2026-05-01-zero-code-mode-index.md`](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md). 옛 M1 redesign spec(`2026-04-30-...`)은 history로만 보존. 본 문서와 충돌하면 spec이 source of truth.

### 왜 필요한가

토스는 OIDC IdP가 아니다 — `/authorize`, JWKS, `state`/PKCE 같은 OIDC 프리미티브가 없고, partner API는 mTLS만 받는다. Supabase Edge Functions(Deno Deploy)와 Firebase Cloud Functions에서는 outbound mTLS가 어렵거나 비포팅이고, **Firebase Spark 플랜은 Cloud Functions의 outbound 외부 호출 자체를 막는다**. Bridge는 그래서 단순 편의가 아니라 integration path 그 자체.

### 운영 모델

- **공용 인스턴스** (`oidc-bridge.aitc.dev`, SLA 없음) — 별도 repo `oidc-bridge-cloud`의 Cloudflare Workers (Workers for Platforms 디스패치 + per-tenant Worker). 본 repo의 Node 서버 코드를 그 곳에서도 ports/adapters로 재사용한다. 운영 절차는 그쪽 repo가 source of truth.
- **Self-host** — 본 repo의 Docker 이미지 + `docker-compose.yml`. rate limit은 기본 ON(`RATE_LIMIT_ENABLED`을 명시적으로 `false`로 설정해야 끈다 — `src/config.ts`). Spark 플랜에서 Firebase Custom Token을 원하면 self-host가 유일한 길(`/firebase-token`은 M2, 아직 미구현).

보안이 민감한 production 사용자는 self-host 권장.

## 아키텍처

### Multi-tenant + DB-backed

영속 상태는 RDB의 7개 테이블 — `users`, `api_tokens`, `workspaces`, `apps`, `user_sessions`, `master_keys`, `audit_log`. mTLS cert/key는 `apps` 컬럼에 per-app sealing key로 봉인 저장, `client_secret`은 bcrypt hash 배열. 그 외 런타임 상태는 in-memory(rate-limit 카운터 등). Bridge가 발급하는 access/refresh token은 **sealed wrapper** — `(app_id, toss_AT, toss_RT, exp)`을 per-app HKDF-derived 키로 AEAD(AES-256-GCM)로 봉인한 opaque string (`ait_<base64url>`). 모든 인스턴스가 같은 master key를 공유하므로 sticky session 없이 unwrap 가능 (cloud invariant).

배포 산출물: 단일 Docker 이미지 (`node:24-alpine`, multi-stage). entrypoint `node dist/server.mjs`, `PORT` default `8080`, `/healthz` → `200 ok`. self-host는 docker-compose + SQLite/PG. 공용 인스턴스(`oidc-bridge.aitc.dev`)는 이 Docker 경로가 아니라 Cloudflare Workers + D1로 운영된다 — 짝 repo [`oidc-bridge-cloud`](https://github.com/apps-in-toss-community/oidc-bridge-cloud) (2026-05-08 cutover, 이전 Vultr/GCP 경로 폐기).

### Storage

Postgres-first + SQLite fallback (이 self-host code base 기준). **self-host multi-app**은 Postgres, **self-host single-app**은 SQLite로 충분(≤1 app 가정). 둘 다 Drizzle ORM(`drizzle-orm` 0.45.x) + drizzle-kit migration. (공용 인스턴스는 이 storage 레이어가 아니라 `oidc-bridge-cloud`의 D1 registry를 쓴다.) 스키마는 dialect별로 hand-mirrored (`schema.pg.ts` / `schema.sqlite.ts`) — Drizzle은 cross-dialect 헬퍼를 제공하지 않으니 storage-conformance 테스트(`runStorageConformance`)가 두 driver의 동일 동작을 보장한다.

`STORAGE` env로 driver 선택 (`pg`|`sqlite`). PG는 `DATABASE_URL`, SQLite는 `SQLITE_PATH`.

### Master keys

DB row는 metadata만. 실제 key bytes는 `MasterKeyProvider`가 외부에서 fetch:
- `env` (`MASTER_KEY_<version>_HEX`) — self-host default
- `file` (`${MASTER_KEY_DIR}/v<version>.key`, perm 600)

`MASTER_KEY_PROVIDER` env로 선택 (`env`|`file`). 6h TTL in-memory cache. Per-app sealing key는 master key + `app_id`로 HKDF 유도 (`info=ait/seal/v1`). Rotation은 아직 CLI 자동화 안 됨 — 수동으로 새 버전 key를 만든 뒤 `apps.sealing_key_version` row를 migrate (old version은 모두 옮길 때까지 유지, lazy rewrap). 절차는 `docs/SELF_HOSTING.md` "Backups & disaster recovery" 섹션 참조.

### `/oidc/token`이 foundational primitive

모든 데이터 경로(`/oidc/userinfo`, `/oidc/revoke`, `/oidc/raw-tokens`)가 sealed AT unwrap → app lookup → mTLS Toss 호출 한 군데에 수렴한다. 새 endpoint 추가 시 이 구조 유지.

### Framework: Hono

Runtime-agnostic + 작은 표면 + 빠른 cold-start + CORS/rate-limit/JWT verify 미들웨어 제공. `@hono/node-server`로 Node 24 위에서 돌리되 Workers 배포 옵션은 미래에도 열려있다. **Fastify/Express 거부** — edge/runtime 이식성과 cold start 때문.

### API 표면

모든 응답 JSON. 에러는 OAuth 2.0/OIDC 관례대로 `{ error, error_description }`.

- **OIDC**: `GET /.well-known/openid-configuration` (`authorization_endpoint`/`response_types_supported`는 의도적 omit — Toss SDK가 OIDC redirect 미지원), `GET /.well-known/jwks.json`, `POST /oidc/token` (`authorization_code`/`refresh_token`. **public client**는 `Origin` 검증으로 인증, **confidential client**는 `client_secret_basic` / `client_secret_post`), `GET /oidc/userinfo` (Bearer → mTLS `/login-me`), `POST /oidc/revoke` (RFC 7009, 항상 200), `GET /oidc/raw-tokens` (opt-in, raw Toss tokens 노출).
- **Admin**: `POST/GET/PATCH/DELETE /admin/workspaces`, `/admin/apps`, `/admin/api-tokens`. `API_TOKEN` bearer로 보호. mTLS material은 GET 응답에서 `***`로 마스킹.
- **CLI**: 번들로 동봉. Admin REST의 thin client + self-host `bootstrap`(offline) + `doctor` 진단 + `user`(offline 사용자 관리: `user create` / `user set-password`).
- **Status**: `GET /status` (Phase 8) HTML 페이지 + `GET /healthz` liveness.

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

## 모듈 구조

상세는 spec §5.2. 요약:

```
src/
  app.ts, server.ts, config.ts, errors.ts
  oidc/         # discovery, jwks, token, userinfo, revoke, raw-tokens,
                # sealed-token (ait_* AEAD+HKDF), id-token, client-auth
  toss/         # client (mTLS Agent), generate-token, refresh-token,
                # login-me, access-remove, envelope, types
  storage/      # interface.ts, schema.pg.ts, schema.sqlite.ts (hand-mirrored),
                # pg.ts, sqlite.ts, migrate.ts
  drizzle/{pg,sqlite}/   # drizzle-kit output (committed)
  master-keys/  # provider, env-provider, file-provider, gcpsm-provider (lazy), cache (6h TTL)
  apps/         # admin REST: workspaces + apps + api_tokens, ownership state machine
  audit/        # audit_log writer
cli/index.ts + cli/commands/{bootstrap,doctor,workspace,app,api-token,user}.ts
```

위 디렉토리는 모두 main에 머지된 상태다 (phase별 진행 현황은 아래 milestone 표 참조).

## Secrets 처리

### Per-app secrets (DB)

mTLS cert + key (PEM)는 `apps` 테이블 컬럼에 per-app sealing key로 봉인 저장 (`bytea`/`BLOB`). `client_secret`은 bcrypt hash 배열만 저장. 평문은 발급/회전 시 한 번만 노출, **회전 overlap 지원**(여러 hash 동시 valid).

### Bridge global secrets (env)

- `OIDC_ISSUER` — discovery에 노출되는 issuer URL.
- `OIDC_SIGNING_KEYS` — RS256 private keys (multi-`kid` rotation). JWKS에 public key만 노출.
- `MASTER_KEY_PROVIDER` — `env`|`file`|`gcpsm`. `env` 모드는 `MASTER_KEY_<version>_HEX` (≥32 bytes hex). `file`은 `MASTER_KEY_DIR`. `gcpsm`은 `oidc-bridge-master-key-v<version>` (lazy import).
- `STORAGE` — `pg`|`sqlite`. `DATABASE_URL`(pg) | `SQLITE_PATH`(sqlite).
- `API_TOKEN` — root admin bearer (bootstrap), 이후 DB의 `api_tokens` row가 일반 경로.
- `TOSS_API_BASE` — default `https://apps-in-toss-api.toss.im`.

### 로딩 관례

모든 secret은 env 또는 DB(per-app). dev는 `dotenv/config`. **로그 금지** — 구조화 logger(pino)가 알려진 secret 키 이름을 redact.

## Rate-limit / 남용 방지 (Phase 8)

초기 phase 범위 밖. Phase 8에서: per-IP sliding-window 카운터(in-memory per instance), `ALLOWED_ORIGINS` env로 CORS allow-list, `/oidc/*` payload 8 KiB cap, 구조화 JSON 로그(PII 없음, `x-request-id` correlation), optional OTel.

## MCP 전략

**공용 MCP는 제공하지 않는다.** `oidc-bridge`의 기능은 전부 표준 OIDC HTTP로 노출되므로 에이전트가 `WebFetch`/`Bash`로 바로 호출 가능. 관리자 전용 remote MCP는 ops introspection용으로 고려하되 HTTP API + OpenTelemetry 구축 후.

## 기술 스택 (repo-specific)

TypeScript ESM strict / **Hono** (+ `@hono/node-server` for Node entry) / **Drizzle ORM** + **drizzle-kit** (Postgres + SQLite + D1, hand-mirrored schemas) / **`pg`** (node-postgres) / **better-sqlite3** (sync, native binding — pnpm `onlyBuiltDependencies`) / **`drizzle-orm/d1`** + **miniflare** (D1 driver + in-memory test harness) / **`@cloudflare/workers-types`** (type-only, dev) / **jose** (ID token sign+verify, JWKS) / **bcryptjs** (client_secret hash) / **undici** (Node mTLS dispatcher, kept behind `MtlsClient` Node adapter) / **commander** (CLI) / **pino** + **pino-pretty** (logging via `Logger` port; Workers entry uses JSON-line adapter) / **WebCrypto `crypto.subtle`** (AEAD, HKDF, digest — primary), **`node:crypto`** (AEAD/HKDF — Node adapter only, behind ports) / **tsdown** 빌드 / **vitest** 테스트.

## 공통 스택

Node 24 LTS, **pnpm 11.17.0** (`packageManager` 고정), TypeScript strict, **Biome** (lint + formatter — ESLint/Prettier 사용 안 함). Pre-commit hook은 source-controlled (`.githooks/pre-commit`)이며, contributor가 수동으로 활성화한다:

```bash
git config core.hooksPath .githooks
```

CI의 `pnpm lint`가 실제 강제 계층, hook은 빠른 피드백 용도. Commit message는 Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).

## 명령어

```bash
pnpm dev                  # watch
pnpm build                # tsdown
pnpm start                # node dist/server.mjs (배포 런타임 진입점)
pnpm typecheck            # tsc --noEmit
pnpm test                 # vitest run (PG_TEST_URL 미설정 시 PG conformance skip)
pnpm lint                 # biome check .
pnpm db:generate:pg       # drizzle-kit generate (pg)
pnpm db:generate:sqlite   # drizzle-kit generate (sqlite)
pnpm db:generate:d1       # drizzle-kit generate (d1)
pnpm db:migrate:pg        # drizzle-kit migrate (pg)
pnpm db:migrate:sqlite    # drizzle-kit migrate (sqlite)
```

전체 스크립트는 `package.json` 참조.

## 테스트 전략

- **Unit (vitest)**: sealing wrap/unwrap roundtrip + tamper rejection, HKDF derivation 결정성, ID token sign+verify, client auth (Basic + Post + bcrypt rotation overlap, public-origin), Toss envelope parsing, claim 매핑, MasterKeyProvider env/file/cache.
- **Storage conformance (`runStorageConformance`)**: pg, sqlite, D1 driver를 같은 테스트 매트릭스로 검증. PG는 `PG_TEST_URL` env로 gate (`describe.skip` if 미설정). D1은 miniflare in-memory `D1Database`로 항상 실행. CI는 `services.postgres: postgres:16-alpine` health-checked.
- **Integration (Hono `app.request()`, no network)**: `/oidc/token` happy + invalid_client + invalid_grant, `/oidc/userinfo` happy + bad bearer, `/oidc/revoke` always-200, discovery+JWKS shape consistency, Admin CRUD with/without token.
- **mTLS**: `https.Agent` 빌드 indirect assertion. 실 핸드셰이크는 `pnpm test:e2e:live` (수동, sandbox cert 필요, CI 아님).
- **Contract fixtures**: `src/__fixtures__/`에 redacted `/generate-token` + `/login-me` SUCCESS/FAIL 응답.
- **CLI**: `--help` smoke + bootstrap/doctor against in-process Bridge.

**Vitest 설정 주의**: `pool: 'forks'`는 top-level (`test.poolOptions.pool` 아님 — Vitest 4에서 제거됨). pg conformance가 진짜 health-checked DB와 통신하므로 fork pool로 격리 필요.

## 릴리즈 정책

**서비스 repo** — main push = 이미지 발행. **Changesets 미사용**, Docker 이미지 tag가 버전 역할. main push → `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>`. Self-host는 자기 인프라에서 `docker compose pull && up -d`(rate limit 기본 ON, `RATE_LIMIT_ENABLED=false`로 해제). 공용 인스턴스(`oidc-bridge.aitc.dev`)는 본 repo가 아니라 `oidc-bridge-cloud` (Cloudflare Workers)에서 따로 배포된다. 의미 있는 마일스톤은 GitHub Release 수동.

## 마일스톤 (Phase 0..11)

12-phase plan. 각 phase는 자체 PR로 main에 머지된 뒤 다음 phase 시작. 인덱스: [`docs/superpowers/plans/2026-05-01-zero-code-mode-index.md`](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md).

| # | Phase | 산출물 | 상태 |
|---|---|---|---|
| 0 | Skeleton | Pino-logging Hono app, `/healthz`, build/lint/test pipelines. Legacy `/verify` 제거. | ✅ main |
| 1 | DB + master-keys | 7-table schema (pg + sqlite), `MasterKeyProvider` (env/file), HKDF, 6h cache. | ✅ main |
| 2 | Admin | Admin REST + CLI (workspaces, apps, api_tokens), bcrypt secrets, mTLS column 봉인, ownership state machine, audit log. | ✅ main |
| 3 | OIDC token (public) | `POST /oidc/token` (public client, origin auth) + JWKS + discovery, mocked Toss. Sealed `ait_*`. | ✅ main |
| 4 | userinfo / revoke / confidential | `GET /oidc/userinfo`, `POST /oidc/revoke`, `GET /oidc/raw-tokens`, confidential-client 인증. | ✅ main |
| 5 | Real Toss mTLS | mTLS adapter, sandbox-fixture capture, error mapping, `test:e2e:live`. | ✅ main |
| 6 | Admin sessions | `user_sessions` + stub session-login (feature flag), CLI `user create` / `user set-password`. | ✅ main |
| 7 | CLI bootstrap/doctor | `bootstrap` (offline), `doctor` 진단 (env/db/master-key/JWKS/optional Toss probe). TTY-aware reporter + `--json`. | ✅ main |
| 8 | Status / rate-limit / observability | `/status` HTML, sliding-window rate limits, pino structured logs, request-id, optional OTel. | ✅ main |
| 09c | Runtime abstraction (Workers-ready core) | `Aead`/`Kdf`/`Random`/`Digest`/`Logger`/`MtlsClient` ports; `Uint8Array` boundaries; D1 storage adapter; `runtime/node.ts` + `runtime/workers.ts` split. Workers entry serves `/healthz` + discovery + JWKS; `/oidc/token` GA는 cloud Phase 12c에서 완료(cloud Worker가 처리). | ✅ main |

Phase 0 + 1은 "zero-code mode" 큰 PR로 main에 한 번에 들어왔다 (#19). 이후 phase는 phase별 단일 PR.

### Cloud separation (10c+) — 별도 repo

09c 이후의 모든 cloud-side phase (`10c` 이상)는 **별도 private repo `oidc-bridge-cloud`**에서 진행된다. 본 repo의 phase matrix는 `09c`에서 정지 — 이 repo는 self-host용 코드 베이스 + cloud Worker가 ports/adapters로 재사용하는 vendor source 역할이다. cloud-side phase plan은 [`docs/superpowers/specs/2026-05-07-cloudflare-cloud-separation.md`](docs/superpowers/specs/2026-05-07-cloudflare-cloud-separation.md) §10이 source of truth.

| Cloud Phase | 상태 | 위치 |
|---|---|---|
| 10c — repo scaffold | ✅ merged | oidc-bridge-cloud#1 |
| 11c — tenant template + DNS cutover + Vultr decommission (옛 13c·14c 흡수) | ✅ merged | oidc-bridge-cloud#3–#10 + oidc-bridge#48 |
| 12c — `MtlsClient` binding + `/oidc/token` GA | ✅ merged | oidc-bridge-cloud#11–#13 |
| 13c — shared Secrets Store + rotation FSM | ✅ merged | oidc-bridge-cloud#16–#38 |
| Self-host phase — generic Docker | ⬜ deferred | oidc-bridge (본 repo) |
| **M5 — sdk-example dog-food on cloud (launch gate)** | ⬜ planned | sdk-example |

본 repo의 `oidc-bridge.aitc.dev` 공용 인스턴스 운영은 **2026-05-08부로 cloud repo로 완전 이관**되었다 — 본 repo의 Vultr SSH-deploy GHA는 [#48](https://github.com/apps-in-toss-community/oidc-bridge/pull/48)에서 제거됐고, `docker-compose.yml` + `Dockerfile`은 self-host 용도로만 보존된다. 본 repo에서 향후 작업 가능성: bug fix, security patch, self-host phase의 generic Docker 정비, vendor-source 업데이트 (cloud repo가 sha pin 갱신할 때 동기화).

## Status

현재 main: zero-code mode Phase 0–8 + 09c 머지됨. 본 repo의 phase plan은 09c에서 정지 — 이후 cloud-side 작업은 `oidc-bridge-cloud` repo에서 진행된다 (위 cloud separation 표). 본 repo는 self-host 코드 베이스 + cloud Worker가 vendor-source로 가져가는 ports/adapters 정본 역할. 옛 `POST /verify` (Basic Auth)는 Phase 0에서 제거됨. 공용 인스턴스(`oidc-bridge.aitc.dev`)는 2026-05-08부로 cloud repo의 Cloudflare Workers로 cutover되어 본 repo의 Vultr deploy 경로는 폐기됨 ([#48](https://github.com/apps-in-toss-community/oidc-bridge/pull/48)). 전체 로드맵은 [landing page](https://aitc.dev/) 참고.

## Standing decisions (Phase 1, 3, 4, 5, 6, 7, 09c에서 굳어진 것)

다음 phase에서도 그대로 따른다. 회고 상세:
- Phase 0+1: [`docs/superpowers/retros/2026-05-02-phase-01-retro.md`](docs/superpowers/retros/2026-05-02-phase-01-retro.md)
- Phase 3: [`docs/superpowers/retros/2026-05-02-phase-03-retro.md`](docs/superpowers/retros/2026-05-02-phase-03-retro.md) (Phase 2 lessons는 PR #22에 흡수됨, 별도 retro 없음)
- Phase 4: [`docs/superpowers/retros/2026-05-02-phase-04-retro.md`](docs/superpowers/retros/2026-05-02-phase-04-retro.md)
- Phase 5: [`docs/superpowers/retros/2026-05-03-phase-05-retro.md`](docs/superpowers/retros/2026-05-03-phase-05-retro.md)
- Phase 6: [`docs/superpowers/retros/2026-05-03-phase-06-retro.md`](docs/superpowers/retros/2026-05-03-phase-06-retro.md)
- Phase 7: [`docs/superpowers/retros/2026-05-05-phase-07-retro.md`](docs/superpowers/retros/2026-05-05-phase-07-retro.md)
- Phase 8: [`docs/superpowers/retros/2026-05-06-phase-08-retro.md`](docs/superpowers/retros/2026-05-06-phase-08-retro.md)

### Runtime abstraction (Phase 09c)

- **Core ports live in `src/core/`, runtime adapters in `src/runtime/`.** `Aead`, `Kdf`, `Random`, `Digest`, `Logger`, `MtlsClient`. Each has a Node adapter (`runtime/node-*.ts`) and a WebCrypto/Workers-friendly default. `Buffer` and `node:crypto` / `node:tls` / `undici` imports are forbidden anywhere in `src/` outside `src/runtime/node-*.ts` (test files excepted, since they always run on Node). `Uint8Array` is the cross-runtime byte type at every port boundary.
- **WebCrypto `seal`/`open` is async**, so `wrapSealedToken` / `unwrapSealedToken` and `encryptColumn` / `decryptColumn` are `async`. All callers `await`. Sealed `ait_*` tokens issued before this phase remain decryptable — the on-the-wire format is locked by golden vectors in `src/oidc/__fixtures__/sealed-token-golden.json` (and equivalent for `apps/encryption`). Cross-impl tests verify Node↔WebCrypto wire interop on the same byte stream.
- **Storage has three drivers** sharing `runStorageConformance`: `pg`, `sqlite`, `d1`. D1 lacks `IF NOT EXISTS` on DDL (workerd SQLite quirk) and rejects DESC in expression indexes — use plain `CREATE` and ascending order in `schema.d1.ts`. miniflare 4 in-memory D1 powers the test suite; D1 migrations apply at deploy time, not per-request.
- **`@cloudflare/workers-types` is type-only**, imported via `import type { D1Database, ... } from '@cloudflare/workers-types'`. Never use `/// <reference types="@cloudflare/workers-types" />` — it pollutes global lib for the whole project (e.g. tightens Node's `TextDecoder` constructor signature so non-Workers files fail to typecheck). `tsconfig.json` `types` array stays `["node"]`.
- **`runtime/workers.ts` must not import `node:*`** and must read env from the Workers `env` parameter, never `process.env`. Production today still runs on Node via `runtime/node.ts`; the Workers entry (09c) compiles and serves `/healthz` + discovery + JWKS. `POST /oidc/token` GA는 cloud Phase 12c에서 완료 — cloud Worker(oidc-bridge-cloud#11–#13)가 mTLS binding을 처리한다.

### pnpm native module builds (allowBuilds)

pnpm은 native module의 install/build script를 기본 차단(security). better-sqlite3는 alpine/musl prebuild를 ship 안 하므로 fallback compile이 필요한데, 그 compile 자체가 차단된다. 해결: `pnpm-workspace.yaml`의 `allowBuilds` 맵에서 `better-sqlite3: true`로 명시 허가. 새 native dep 추가 시 같은 맵에 `<name>: true`를 추가한다. (pnpm 11부터 `onlyBuiltDependencies`/`ignoredBuiltDependencies`는 더 이상 읽히지 않는다 — 선언 안 된 install script는 경고가 아니라 `ERR_PNPM_IGNORED_BUILDS`로 install 자체가 실패한다.)

### Alpine builder toolchain

runtime image는 `node:24-alpine` 유지(슬림). 그러나 builder stage는 `apk add --no-cache python3 make g++` 필요 — better-sqlite3가 musl 환경에서 `node-gyp rebuild` fallback을 타기 때문. runtime stage로는 prune된 `node_modules`만 복사하므로 final 이미지 크기는 보존된다.

### Drizzle 0.45.2 함정 (hand-mirrored schemas)

- `bytea` customType은 `drizzle-orm/pg-core` 0.45.2에서 export되지 않음 — 직접 정의해서 쓴다.
- `updatedAt` 컬럼은 `.defaultNow()`만으로는 UPDATE 시 stale. **`$onUpdateFn(() => new Date())` 필수**.
- SQLite expression index에 DESC 사용 가능(empirical로 동작 — review에서 잘못된 지적이 들어와도 무시).
- `OWNERSHIP_STATUSES` 같은 enum-ish 컬럼은 DB-level CHECK가 없으면 런타임 가드(`Set<string>`)로 검증.
- `updateWorkspace(patch)` 같은 partial-update는 empty patch에서 Drizzle이 "No values to set" throw하므로 호출부에서 가드.

### 테스트 패턴

- 두 driver를 검증하는 `runStorageConformance(name, { open, cleanup })` 팩토리. SQLite는 항상 실행, PG는 `PG_TEST_URL` env gate로 `describe.skip`.
- CI는 `services.postgres: postgres:16-alpine` health-checked + job-level `env: PG_TEST_URL`.
- TRUNCATE-before-each-open 패턴으로 테스트 간 격리. migration은 idempotent(`runPgMigrations`).
- Vitest 4: `pool: 'forks'`는 **top-level** (`test.poolOptions` 제거됨).

### Subagent 위임 가이드라인

- `Agent` 호출 시 `model` 명시: 단순 mirror/lookup은 **haiku**, 일반 구현은 **sonnet**, 어려운 설계는 **opus**. 생략하면 부모(opus)를 상속해서 단순 작업도 비싸진다.
- mirror task(예: PG driver가 SQLite의 structural mirror)는 quality review skip 가능. spec compliance review는 항상.
- Subagent reviewer가 잘못된 주장(e.g. "SQLite expression index DESC 안 됨")을 할 때는 empirical refute로 끝내고 진행. 끌려가지 않는다.
- 실행 흐름은 `superpowers:subagent-driven-development` skill에 정리되어 있다.

### Repo-specific PR 운영

한 phase = 한 PR = main으로 squash merge. `gh pr merge --delete-branch`이 메인 worktree가 main을 점유 중일 때 실패하면, 머지는 GitHub 쪽에서 이미 끝났으니 메인 worktree에서 `git pull --ff-only`로 동기화.
