# CLAUDE.md

## 프로젝트 성격

비공식(unofficial) 커뮤니티 프로젝트. 사용자에게 보이는 산출물에서 "공식/official/powered by Toss" 등 제휴·인증 암시 표현 금지. 공용 인스턴스는 **rate-limited, best-effort, community-operated**. 상세는 umbrella [`CLAUDE.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/CLAUDE.md)의 "프로젝트 성격" 참조.

## 짝 repo

- **`sdk-example`** — bridge M5 launch gate가 여기로 묶인다. sdk-example의 `AuthPage`가 옛 `POST /verify`를 버리고 Supabase Edge Function (`supabase/functions/toss-login`)으로 `/oidc/token` → `signInWithIdToken` 경로를 만든다. 이 Edge Function이 README와 `agent-plugin` 템플릿의 canonical reference.
- **`agent-plugin`** — `/ait new` auth 옵션이 이 bridge를 가리킨다.

다른 repo와의 전체 짝 그림은 umbrella [`CLAUDE.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/CLAUDE.md)의 "짝(pair) 관계" 참조. 기본적으로 **독립 서비스** — launch만 sdk-example dog-fooding에 묶인다.

## 프로젝트 개요

**oidc-bridge** — 토스 로그인을 표준 OIDC 어댑터로 중계해서 mini-app 운영자가 Supabase / Firebase / Auth0 / Keycloak 같은 일반 IdP 통합 흐름으로 토스 로그인을 붙일 수 있게 해주는 multi-tenant 서버.

전체 설계는 [`docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md`](docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) (zero-code mode). 12-phase 구현 인덱스는 [`docs/superpowers/plans/2026-05-01-zero-code-mode-index.md`](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md). 옛 M1 redesign spec(`2026-04-30-...`)은 history로만 보존. 본 문서와 충돌하면 spec이 source of truth.

### 왜 필요한가

토스는 OIDC IdP가 아니다 — `/authorize`, JWKS, `state`/PKCE 같은 OIDC 프리미티브가 없고, partner API는 mTLS만 받는다. Supabase Edge Functions(Deno Deploy)와 Firebase Cloud Functions에서는 outbound mTLS가 어렵거나 비포팅이고, **Firebase Spark 플랜은 Cloud Functions의 outbound 외부 호출 자체를 막는다**. Bridge는 그래서 단순 편의가 아니라 integration path 그 자체.

### 운영 모델

- **공용 인스턴스** (`oidc-bridge.aitc.dev`, SLA 없음) — Vultr Cloud Compute Seoul 단일 VPS + Docker + Caddy. ~$5/mo (`vc2-1c-1gb`).
- **Self-host** — 동일 Docker 이미지 + 동일 `docker-compose.yml`. `RATE_LIMIT_ENABLED=false` 기본. Spark 플랜에서 Firebase Custom Token을 원하면 self-host가 유일한 길.

보안이 민감한 production 사용자는 self-host 권장.

## 아키텍처

### Multi-tenant + DB-backed

영속 상태는 RDB의 7개 테이블 — `users`, `api_tokens`, `workspaces`, `apps`, `user_sessions`, `master_keys`, `audit_log`. mTLS cert/key는 `apps` 컬럼에 per-app sealing key로 봉인 저장, `client_secret`은 bcrypt hash 배열. 그 외 런타임 상태는 in-memory(rate-limit 카운터 등). Bridge가 발급하는 access/refresh token은 **sealed wrapper** — `(app_id, toss_AT, toss_RT, exp)`을 per-app HKDF-derived 키로 AEAD(AES-256-GCM)로 봉인한 opaque string (`ait_<base64url>`). 모든 인스턴스가 같은 master key를 공유하므로 sticky session 없이 unwrap 가능 (cloud invariant).

배포 산출물: 단일 Docker 이미지 (`node:24-alpine`, multi-stage). entrypoint `node dist/server.mjs`, `PORT` default `8080`, `/healthz` → `200 ok`. 공용 인스턴스는 GCP Cloud Run + Cloud SQL pg(Phase 10), self-host는 docker-compose + SQLite/PG.

### Storage

Postgres-first + SQLite fallback. **공용 인스턴스는 Postgres**(Cloud SQL), **self-host single-app**은 SQLite로 충분(≤1 app 가정). 둘 다 Drizzle ORM(`drizzle-orm` 0.45.x) + drizzle-kit migration. 스키마는 dialect별로 hand-mirrored (`schema.pg.ts` / `schema.sqlite.ts`) — Drizzle은 cross-dialect 헬퍼를 제공하지 않으니 storage-conformance 테스트(`runStorageConformance`)가 두 driver의 동일 동작을 보장한다.

`STORAGE` env로 driver 선택 (`pg`|`sqlite`). PG는 `DATABASE_URL`, SQLite는 `SQLITE_PATH`.

### Master keys

DB row는 metadata만. 실제 key bytes는 `MasterKeyProvider`가 외부에서 fetch:
- `env` (`MASTER_KEY_<version>_HEX`) — self-host default
- `file` (`${MASTER_KEY_DIR}/v<version>.key`, perm 600)
- `gcpsm` (`oidc-bridge-master-key-v<version>`) — 공용 인스턴스 default, lazy import

`MASTER_KEY_PROVIDER` env로 선택. 6h TTL in-memory cache. Per-app sealing key는 master key + `app_id`로 HKDF 유도 (`info=ait/seal/v1`). Rotation은 `cli master-key rotate` — old version retained until 모든 `apps.sealing_key_version`이 새로 migrate, lazy rewrap.

### `/oidc/token`이 foundational primitive

모든 데이터 경로(`/oidc/userinfo`, `/oidc/revoke`, `/oidc/raw-tokens`)가 sealed AT unwrap → app lookup → mTLS Toss 호출 한 군데에 수렴한다. 새 endpoint 추가 시 이 구조 유지.

### Framework: Hono

Runtime-agnostic + 작은 표면 + 빠른 cold-start + CORS/rate-limit/JWT verify 미들웨어 제공. `@hono/node-server`로 Node 24 위에서 돌리되 Workers 배포 옵션은 미래에도 열려있다. **Fastify/Express 거부** — edge/runtime 이식성과 cold start 때문.

### API 표면

모든 응답 JSON. 에러는 OAuth 2.0/OIDC 관례대로 `{ error, error_description }`.

- **OIDC**: `GET /.well-known/openid-configuration` (`authorization_endpoint`/`response_types_supported`는 의도적 omit — Toss SDK가 OIDC redirect 미지원), `GET /.well-known/jwks.json`, `POST /oidc/token` (`authorization_code`/`refresh_token`. **public client**는 `Origin` 검증으로 인증, **confidential client**는 `client_secret_basic` / `client_secret_post`), `GET /oidc/userinfo` (Bearer → mTLS `/login-me`), `POST /oidc/revoke` (RFC 7009, 항상 200), `GET /oidc/raw-tokens` (opt-in, raw Toss tokens 노출).
- **Admin**: `POST/GET/PATCH/DELETE /admin/workspaces`, `/admin/apps`, `/admin/api-tokens`. `API_TOKEN` bearer로 보호. mTLS material은 GET 응답에서 `***`로 마스킹.
- **CLI**: 번들로 동봉. Admin REST의 thin client + self-host `bootstrap`(offline) + `doctor` 진단.
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
cli/index.ts + cli/commands/{bootstrap,doctor,workspace-*,app-*,api-token-*,master-key-rotate}.ts
```

Phase 0 + Phase 1 산출물(`storage/`, `master-keys/`)은 main에 머지됨. 그 외 디렉토리는 후속 phase에서 추가.

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

**공용 MCP는 제공하지 않는다.** `oidc-bridge`의 기능은 전부 표준 OIDC HTTP로 노출되므로 에이전트가 `WebFetch`/`Bash`로 바로 호출 가능. 관리자 전용 remote MCP는 ops introspection용으로 고려하되 HTTP API + OpenTelemetry 구축 후. 판별 기준은 umbrella [`meta/mcp-strategy.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/meta/mcp-strategy.md) 참조.

## 기술 스택 (repo-specific)

TypeScript ESM strict / **Hono** (+ `@hono/node-server`) / **Drizzle ORM** + **drizzle-kit** (Postgres + SQLite, hand-mirrored schemas) / **`pg`** (node-postgres) / **better-sqlite3** (sync, native binding — pnpm `onlyBuiltDependencies`) / **jose** (ID token sign+verify, JWKS) / **bcryptjs** (client_secret hash) / **@google-cloud/secret-manager** (lazy) / **undici** (HTTP/mTLS dispatcher) / **commander** (CLI) / **pino** + **pino-pretty** (logging) / **node:crypto** + **node:tls** (AEAD, HKDF, mTLS Agent) / **tsdown** 빌드 / **vitest** 테스트.

조직 공통 스택(Node 24, pnpm 10.33.0, Biome lint+format, pre-commit hook 등)은 umbrella [`CLAUDE.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/CLAUDE.md)의 "공통 스택" 참조.

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
pnpm db:migrate:pg        # drizzle-kit migrate (pg)
pnpm db:migrate:sqlite    # drizzle-kit migrate (sqlite)
```

전체 스크립트는 `package.json` 참조.

## 테스트 전략

- **Unit (vitest)**: sealing wrap/unwrap roundtrip + tamper rejection, HKDF derivation 결정성, ID token sign+verify, client auth (Basic + Post + bcrypt rotation overlap, public-origin), Toss envelope parsing, claim 매핑, MasterKeyProvider env/file/cache.
- **Storage conformance (`runStorageConformance`)**: pg와 sqlite driver를 같은 테스트 매트릭스로 검증. PG는 `PG_TEST_URL` env로 gate (`describe.skip` if 미설정). CI는 `services.postgres: postgres:16-alpine` health-checked.
- **Integration (Hono `app.request()`, no network)**: `/oidc/token` happy + invalid_client + invalid_grant, `/oidc/userinfo` happy + bad bearer, `/oidc/revoke` always-200, discovery+JWKS shape consistency, Admin CRUD with/without token.
- **mTLS**: `https.Agent` 빌드 indirect assertion. 실 핸드셰이크는 `pnpm test:e2e:live` (수동, sandbox cert 필요, CI 아님).
- **Contract fixtures**: `src/__fixtures__/`에 redacted `/generate-token` + `/login-me` SUCCESS/FAIL 응답.
- **CLI**: `--help` smoke + bootstrap/doctor against in-process Bridge.

**Vitest 설정 주의**: `pool: 'forks'`는 top-level (`test.poolOptions.pool` 아님 — Vitest 4에서 제거됨). pg conformance가 진짜 health-checked DB와 통신하므로 fork pool로 격리 필요.

## 릴리즈 정책

**Type C (서비스 repo)**. main push = 배포. **Changesets 미사용**, Docker 이미지 tag가 버전 역할. 공용 인스턴스: main push → `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>` → SSH로 Vultr Seoul VPS에 `docker compose pull && up -d` (`.github/workflows/deploy.yml`). 상세 셋업은 [`docs/DEPLOY.md`](./docs/DEPLOY.md). Self-host는 동일 이미지를 자기 인프라에 (`RATE_LIMIT_ENABLED=false` 기본). 의미 있는 마일스톤은 GitHub Release 수동.

조직 전체 release 정책 매트릭스는 umbrella [`CLAUDE.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/CLAUDE.md) 및 [`meta/release-strategy.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/meta/release-strategy.md) 참조.

## TODO

조직 단일 source는 umbrella [`TODO.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/TODO.md). 이 repo의 `TODO.md`는 umbrella를 가리키는 stub.

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
| **8** | **Status / rate-limit / observability** | **`/status` HTML, sliding-window rate limits, pino structured logs, request-id, optional OTel.** | **진행 예정** |
| 9 | Self-host artifacts | Dockerfile + docker-compose + SECURITY.md + SELF_HOSTING.md, clean-VPS smoke. | |
| 10 | GCP Cloud Run | Cloud Run + Cloud SQL pg + GCPSM master keys + Cloud Build, DNS to `oidc-bridge.aitc.dev`. | |
| **11** | **sdk-example dog-fooding (M5 launch gate)** | sdk-example legacy `/verify` 경로를 `appLogin → /oidc/token → signInWithIdToken`으로 교체. | |

Phase 0 + 1은 "zero-code mode" 큰 PR로 main에 한 번에 들어왔다 (#19). 이후 phase는 phase별 단일 PR.

## Status

현재 main: zero-code mode Phase 0–7 머지됨 (#19, #20, #21, #22, #24, #25, #26, #27, #29, #32, #34). 다음은 Phase 8 (`/status` + rate-limit + observability). 옛 `POST /verify` (Basic Auth)는 Phase 0에서 제거됨. 전체 로드맵은 [landing page](https://apps-in-toss-community.github.io/) 참고.

## Standing decisions (Phase 1, 3, 4, 5, 6, 7에서 굳어진 것)

다음 phase에서도 그대로 따른다. 회고 상세:
- Phase 0+1: [`docs/superpowers/retros/2026-05-02-phase-01-retro.md`](docs/superpowers/retros/2026-05-02-phase-01-retro.md)
- Phase 3: [`docs/superpowers/retros/2026-05-02-phase-03-retro.md`](docs/superpowers/retros/2026-05-02-phase-03-retro.md) (Phase 2 lessons는 PR #22에 흡수됨, 별도 retro 없음)
- Phase 4: [`docs/superpowers/retros/2026-05-02-phase-04-retro.md`](docs/superpowers/retros/2026-05-02-phase-04-retro.md)
- Phase 5: [`docs/superpowers/retros/2026-05-03-phase-05-retro.md`](docs/superpowers/retros/2026-05-03-phase-05-retro.md)
- Phase 6: [`docs/superpowers/retros/2026-05-03-phase-06-retro.md`](docs/superpowers/retros/2026-05-03-phase-06-retro.md)
- Phase 7: [`docs/superpowers/retros/2026-05-05-phase-07-retro.md`](docs/superpowers/retros/2026-05-05-phase-07-retro.md)

### pnpm 10 + native modules

pnpm 10은 native module의 install/build script를 기본 차단(security). better-sqlite3는 alpine/musl prebuild를 ship 안 하므로 fallback compile이 필요한데, 그 compile 자체가 차단된다. 해결: `package.json`의 `pnpm.onlyBuiltDependencies: ["better-sqlite3"]`로 명시 허가. 새 native dep 추가 시 같은 배열에 추가.

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

### Repo-specific commit/PR

- Conventional Commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`).
- 한 phase = 한 PR = main으로 squash merge. `gh pr merge --delete-branch`이 메인 worktree가 main을 점유 중일 때 실패하면, 머지는 GitHub 쪽에서 이미 끝났으니 메인 worktree에서 `git pull --ff-only`로 동기화.
