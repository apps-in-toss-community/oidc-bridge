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

- **공용 인스턴스** (rate-limited, best-effort, SLA 없음)
- **Self-host** (Docker/Fly.io/Cloud Run)

보안이 민감한 production 사용자는 self-host를 권장.

한국 리전이 있는 호스팅이 요구사항이며, 공용 인스턴스는 **Google Cloud Run (`asia-northeast3`, Seoul)** 기반이 1순위 후보 (scale-to-zero + Docker 이미지 네이티브 + free tier 내 운영 가능).

## 기술 스택

- **TypeScript** (ESM only, strict)
- **tsdown** — 빌드
- **vitest** — 테스트
- **pnpm** — 패키지 매니저 (10.33.0)
- **Biome** — lint + formatter (조직 표준)
- **Changesets 사용 안 함** — Type C (서비스 repo). `main` = 배포. Docker 이미지 tag가 버전 역할.

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

## 배포 모델

- **공용 인스턴스**: main push → Docker 이미지 빌드 → `ghcr.io/apps-in-toss-community/oidc-bridge:latest` + `:sha-<sha>` → Cloud Run 자동 배포 (향후 설정)
- **Self-host**: 사용자가 동일 Docker 이미지를 자신의 인프라(Docker/Fly.io/Cloud Run/k8s)에 올림. `RATE_LIMIT_ENABLED=false` 기본값.

## Status

scaffold 완료, 구현 전. `src/server.ts`는 placeholder.

전체 로드맵은 [landing page](https://apps-in-toss-community.github.io/) 참고.
