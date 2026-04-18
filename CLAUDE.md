# CLAUDE.md

## 프로젝트 성격 (중요)

**`apps-in-toss-community`는 비공식(unofficial) 오픈소스 커뮤니티다.** 토스 팀과 제휴 없음. 사용자에게 보이는 산출물에서 "공식/official/토스가 제공하는/powered by Toss" 등 제휴·후원·인증 암시 표현을 **쓰지 않는다**. 대신 "커뮤니티/오픈소스/비공식"을 사용한다. 의심스러우면 빼라.

특히 공용 인스턴스를 운영할 때 **rate-limited, best-effort, community-operated**임을 명시. production용 보증 없음.

## 짝 repo

- **`sdk-example`** (downstream consumer) — oidc-bridge가 완성되면 sdk-example의 auth 섹션이 실제 토스 로그인 → Supabase/Firebase 세션까지의 **E2E 흐름을 데모**한다. 이게 bridge의 주요 품질 게이트.
- **`agent-plugin`** — `/ait new`에서 auth 옵션으로 Supabase/Firebase/Auth0를 선택하면 이 bridge를 가리키는 설정을 템플릿에 주입.

기본적으로 **독립 서비스**. 다른 repo 변경 없이 배포 가능.

## 프로젝트 개요

**oidc-bridge** — 토스 로그인을 **표준 OIDC provider**와 **Firebase Custom Token 발급기**로 중계하는 서버.

### 왜 필요한가

토스 로그인은 독점 프로토콜이라 Supabase Auth, Firebase Auth, Auth0 같은 표준 IdP에 바로 연결되지 않는다. 이 서버가 중간에서:

1. **OIDC provider 역할** — `/.well-known/openid-configuration`, `/authorize`, `/token`, JWKS 제공. 표준 OIDC 클라이언트가 바로 붙을 수 있음.
2. **Firebase Custom Token 발급** — Firebase Admin SDK로 서명된 custom token을 반환. 클라이언트는 `signInWithCustomToken`으로 사용.

### 운영 모델

- **공용 인스턴스** (rate-limited, best-effort, SLA 없음) — Google Cloud Run `asia-northeast3` (Seoul). scale-to-zero + Docker 이미지 네이티브 + free tier 내 운영 가능해서 1순위.
- **Self-host** (Docker/Fly.io/Cloud Run/k8s) — 동일 Docker 이미지. `RATE_LIMIT_ENABLED=false` 기본.

보안이 민감한 production 사용자는 self-host를 권장.

## 아키텍처

### Stateless HTTP

- **DB 없음, Redis 없음, 세션 스토어 없음.** 각 요청: Toss `authorizationCode` in → verified claims / token out. 요청 간 서버 상태 없음.
- Rate-limit 카운터만 **in-memory per-instance** (§ rate-limit 전략 참고). 공용 인스턴스의 "best-effort" 약속에 비추면 충분. 전역 rate-limit이 필요한 self-host는 앞단에 API gateway를 두라.
- 배포 산출물은 **단일 Docker 이미지** (`node:24-alpine`, multi-stage). entrypoint `node dist/server.mjs`, `PORT` (default `8080`, Cloud Run 규약), `/healthz` → `200 ok`.

### `/verify`는 foundational primitive

모든 다른 endpoint(`/firebase-token`, OIDC `/token`)가 내부적으로 `verify()`를 재사용한다. "Toss code → verified claims" 한 군데에만 존재한다. 새 endpoint를 추가할 때 이 구조를 깨뜨리지 말 것.

### Framework: Hono

**Hono** 선택. 이유:

- **Runtime-agnostic** (Node, Bun, Deno, Cloud Run, Cloudflare Workers, Vercel). 공용 인스턴스는 Cloud Run `asia-northeast3`로 가고, self-hoster는 자기가 쓰는 무엇이든 올리고 싶어할 것.
- **작은 표면 + 빠른 cold-start** — Cloud Run scale-to-zero에 유의미.
- **CORS / rate-limit / JWT verify 미들웨어 제공**.
- `@hono/node-server`로 Node 24(조직 스택) 위에서 바로 돌리되, Workers 배포 옵션은 미래에도 열려있음.

**Fastify / Express는 거부** — Node에서는 괜찮지만 edge/runtime 이식성이 떨어지고 cold start가 무겁다. Hono는 우리가 신경 쓰는 걸 잃지 않으면서 이식성에서 이김.

### API 표면 (v0)

모든 응답 JSON. 에러는 OAuth 2.0 / OIDC 관례대로 `{ error, error_description }`.

- `POST /verify` — foundational (현재 `501 not_implemented` 스텁). 요청: `{ authorizationCode, referrer }`. 응답: `{ sub, provider: "toss", claims, tossAccessTokenExpiresAt }`.
- `POST /firebase-token` — `/verify` 위에 Firebase custom token 서명. `FIREBASE_SERVICE_ACCOUNT` 없으면 `501 not_configured`. 공용 인스턴스는 **end-user service account를 안 들고 있음**. self-host 전용.
- OIDC provider surface (`/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/authorize`, `/token`, `/userinfo`) — follow-up PR. Supabase / Auth0 / Keycloak가 바닐라 OIDC IdP로 꽂아 쓸 수 있게.
- `GET /healthz` — liveness.

## Toss token verification — open questions + 문서화된 가정

**전제**: 아래 내용은 2026-04 기준 퍼블릭 developer center 문서에 근거. 문서가 바뀌거나 production에서 불일치를 발견하면 여기가 TODO 목록이 된다.

### 흐름 (현재 가정)

1. Mini-app `appLogin()` → `{ authorizationCode, referrer }` (10분 유효).
2. Bridge → `POST https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss/user/oauth2/generate-token`, body `{ authorizationCode, referrer }`.
3. 응답: `{ accessToken (JWT), refreshToken, tokenType: "Bearer", expiresIn: 3599, scope }`.
4. Bridge는 `refreshToken`을 기본적으로 호출자에 **전달하지 않음**. stateless verify 경로에 쓸 데가 없고 노출하면 blast radius만 커짐.
5. (옵션, 요청별 플래그) `/oauth2/login-me`로 `userKey`, `scope`, `agreedTerms` 조회. PII 필드는 AES-256-GCM 암호화되어 옴 — § PII 참고.

### Open questions

1. **partner API 인증 스킴** — `generate-token` 요청 auth가 Basic auth인지, `X-Client-Id`/`X-Client-Secret` 헤더인지, 또는 body에 `client_id`/`client_secret`인지. 문서 확인 또는 동작하는 샘플로 검증 필요. 가정: 도입 초기엔 header 방식, PR로 확정.
2. **AT 서명 검증 경로** — 후보 (가능성 순): (a) Toss가 JWKS URL을 퍼블리시 → fetch + cache. (b) partner `client_secret` 기반 HS256 shared secret. (c) 퍼블릭 JWKS 없고 AT는 opaque → `/login-me` 왕복이 사실상 검증.
3. **`/login-me`는 매 verify 필수인가 opt-in인가** — 현재 계획 opt-in. 다만 `sub` 안정성이 `/login-me`의 `userKey`에 의존하면 mandatory로 강제될 수 있음.
4. **공용 인스턴스 OIDC signing key 회전 주기** — 90일? 설정 가능? v0에선 수동 회전 + 공지.
5. **partner 사전 등록 없이 per-partner rate bucket을 제공할지** — v0는 "no". per-IP만.

### 스캐폴드 초기의 가정 (pre-stable gap)

V0 `/verify`는 실제 구현되면 `generate-token` 응답을 **단일 검증 신호**로 신뢰하고 AT claim은 decode만 하되 암호학적 서명 검증은 하지 않는다. 이는 pre-stable 갭으로 명시하며, 후속 PR(M1)에서 닫는다. `/verify` 응답에 이 사실이 드러나게 해 consumer가 알 수 있도록.

### Claim 매핑

| Bridge claim | Source |
|---|---|
| `sub` | `/login-me`의 `userKey` (세션 간 안정) — 또는 `/login-me` skip 시 AT의 `sub` |
| `provider` | 상수 `"toss"` |
| `aud` | bridge issuer config |
| `claims.scopes` | AT `scope` split |
| `claims.userKey` | `/login-me`의 `userKey` |
| `claims.agreedTerms` | `/login-me`의 `agreedTerms` |

PII 필드(name/phone/birthday/CI/gender/nationality)는 기본적으로 `claims`에 넣지 **않음**. 암호화된 채로 통과되며, 요청별 opt-in (`include: ["name", ...]`)으로만 노출. § PII 참고.

## Rate-limit 전략

### 공용 인스턴스

- **전략**: per-IP sliding-window 카운터, in-memory per instance.
- **기본값**: `/verify` family 60 req/min/IP. `/firebase-token`은 `/verify`를 감싸므로 같은 버킷.
- **per-partner (client_id) 제한**은 follow-up — partner 등록 UX가 필요한데 아직 없음. v0는 per-IP만.
- **Cloud Run 동작**: scale-to-zero 시 카운터 리셋 → best-effort 전제상 수용. multi-instance 시 유효 제한 = `limit × instance_count`. 문서에 명시.
- **헤더**: 모든 응답에 `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`. 429엔 `Retry-After` 추가.
- **Self-host opt-out**: `RATE_LIMIT_ENABLED=false` (공용 Docker 이미지 default `true`, dev default `false`).

### 추가 남용 방지

- `ALLOWED_ORIGINS` env로 CORS allow-list.
- `/verify` + `/firebase-token` payload 8 KiB cap.
- 구조화 JSON 로그, PII 없음, `x-request-id` correlation.
- `referrer`는 allow-list 밖 (`DEFAULT`, `SANDBOX` 외)이면 거부.

## Secrets 처리

### Toss partner 자격증명

- `TOSS_CLIENT_ID`
- `TOSS_CLIENT_SECRET`
- `TOSS_API_BASE` (default `https://apps-in-toss-api.toss.im`, 샌드박스 오버라이드용)

### Firebase service account (self-host 전용, v0)

- `FIREBASE_SERVICE_ACCOUNT` — raw JSON 또는 base64.
- `GOOGLE_APPLICATION_CREDENTIALS` — JSON 경로, 대안.
- Lazy init. 없으면 `/firebase-token` → `501 not_configured`.

**공용 인스턴스는 end-user Firebase service account를 보관하지 않는다.** Firebase custom token을 원하는 mini-app 운영자는 self-host 해야 한다. 공용 인스턴스는 `/verify` + OIDC provider surface만 노출(여기선 bridge 자체가 IdP, 자체 키로 서명).

### OIDC signing key (provider surface, follow-up)

- `OIDC_SIGNING_KEY` — PEM RSA/EC private key.
- `OIDC_ISSUER` — consumer가 whitelist할 issuer URL.
- JWKS는 이로부터 유도해 `/.well-known/jwks.json`에 제공.
- 공용 인스턴스: 스케줄 회전, 회전 이벤트 공지.

### PII / `/login-me` decryption key

- `TOSS_PII_DECRYPTION_KEY` — optional.
- 없을 때: bridge는 암호화된 필드를 그대로 패스스루. 호출자(PII 관계의 법적 주체)가 자기 쪽에서 복호화.
- 있을 때: 호출자가 `include: [...]`로 명시적 opt-in한 필드만 bridge가 복호화. default-off, per-request 명시.

### 로딩 관례

- 모든 secret은 env var. dev는 `dotenv/config`.
- **로그 금지**. 구조화 logger가 알려진 secret 키 이름을 redact.
- v0엔 DB 기반 secret 없음.

## MCP 전략

**공용 MCP는 제공하지 않는다.** 이유:

- 공용 remote MCP는 인증/레이트리밋/민감 데이터 노출 설계 비용이 큼 (umbrella `CLAUDE.md` MCP 판별 체크리스트 참고).
- `oidc-bridge`의 기능은 전부 순수 HTTP로 노출 가능. 에이전트가 `WebFetch`/`Bash`로 바로 호출 가능.
- 관리자 전용 remote MCP는 ops introspection용으로 고려하되 HTTP API + OpenTelemetry를 먼저 구축한 뒤. v0 밖.

## 기술 스택

- **TypeScript** (ESM only, strict)
- **Hono** — HTTP framework (+ `@hono/node-server`)
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

- **vitest (unit)**: claim 매핑, rate limiter, error envelope shape.
- **Integration**: `app.request()`로 Hono app을 in-process 호출 — 네트워크 없음. Toss upstream은 `fetch` 레이어에서 mock.
- **Contract fixtures**: scaffold 다음으로 `src/__fixtures__/`에 redacted `/generate-token` + `/login-me` 응답 커밋.
- **E2E against real Toss**: `pnpm test:e2e:live`(수동, sandbox 자격증명 필요). CI 아님.

## 릴리즈 정책

- **Type C (서비스 repo).** main push = 배포.
- **Changesets 사용 안 함.** 버전 개념 없음. Docker 이미지 tag가 버전 역할.
- **공용 인스턴스**: main push → Docker 이미지 빌드 → `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>` → Cloud Run 자동 배포 (M5 workflow에서).
- **Self-host**: 사용자가 동일 이미지를 자기 인프라에. `RATE_LIMIT_ENABLED=false` 기본.
- 의미 있는 마일스톤은 GitHub Release를 수동으로 남겨 self-host 사용자가 구독/핀할 수 있게.

## 마일스톤

| # | 내용 | 상태 |
|---|---|---|
| M0 | Hono scaffold + `/verify` 스텁 + Dockerfile + CI green | **완료 (현재 PR)** |
| M1 | 실제 `/verify` 구현 (Toss `generate-token`), JWT 서명 검증 경로 확정 | next |
| M2 | `/firebase-token` + Firebase Admin (self-host) | next |
| M3 | Rate-limit 미들웨어 + CORS + payload cap | next |
| M4 | OIDC provider surface (`/authorize`, `/token`, JWKS) | follow-on |
| M5 | 공용 인스턴스용 Cloud Run 배포 workflow | follow-on |
| M6 | `sdk-example` auth 데모를 공용 인스턴스에 연결 | M4 이후 |

## Status

scaffold 완료, 구현 전. `src/server.ts`는 placeholder.

전체 로드맵은 [landing page](https://apps-in-toss-community.github.io/) 참고.
