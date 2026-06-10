# oidc-bridge

**한국어** · [English](./README.en.md)

토스 로그인을 BaaS 플랫폼(Supabase, Firebase, Auth0, Keycloak 등)으로 연결해주는 커뮤니티 OIDC 어댑터.

## 동작 방식

미니앱 개발자가 Bridge에 앱을 등록하면 `client_id`와 `iss = https://oidc-bridge.aitc.dev` OIDC 발급자 URL을 받습니다. 미니앱은 `appLogin()`을 호출해 토스 `authorizationCode`를 받고, `POST /oidc/token`에서 OIDC `id_token`으로 교환한 뒤 `signInWithIdToken`으로 Supabase에 로그인합니다. 별도 백엔드 코드가 필요 없습니다(zero-code 모드).

서버 권한이 필요한 Edge Function / Cloud Function 운영자는 동일한 `/oidc/token` 엔드포인트에서 `client_secret` 인증(confidential-client 모드)을 사용할 수 있습니다.

## 상태

2026년 5월 기준 zero-code 모드의 self-host 코드 베이스(Phase 0–8 및 09c)가 `main`에 머지되어 이 repo의 phase plan은 09c에서 정지했습니다. 이후 cloud-side 작업은 별도 private repo `oidc-bridge-cloud`에서 진행됩니다. 참조:

- [설계 스펙](docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md) — 전체 아키텍처, 컴포넌트, 보안 모델.
- [구현 인덱스](docs/superpowers/plans/2026-05-01-zero-code-mode-index.md) — 단계별 계획.
- [`MIGRATION.md`](./MIGRATION.md) — M0 이후 브레이킹 체인지.

| Phase | 내용 | PR |
|---|---|---|
| 0 | Pino 로깅 Hono 앱, `/healthz`, 빌드/린트/테스트 파이프라인. 레거시 `/verify` 제거. | [#19](https://github.com/apps-in-toss-community/oidc-bridge/pull/19) |
| 1 | 7-테이블 스키마(pg + sqlite), `MasterKeyProvider`, HKDF, 6h 키 캐시. | [#19](https://github.com/apps-in-toss-community/oidc-bridge/pull/19) |
| 2 | Admin REST + CLI(workspaces, apps, api_tokens), bcrypt secrets, mTLS 컬럼 암호화, ownership state machine, audit log. | [#20](https://github.com/apps-in-toss-community/oidc-bridge/pull/20), [#21](https://github.com/apps-in-toss-community/oidc-bridge/pull/21) |
| 3 | `POST /oidc/token`(public client) + JWKS + discovery, mocked Toss. | ✅ main |
| 4–09c | userinfo + revoke, real Toss mTLS, admin sessions, CLI bootstrap, observability, runtime abstraction(Workers-ready). | ✅ main |
| 10c+ | tenant template, DNS cutover, MtlsClient binding, `/oidc/token` GA. | oidc-bridge-cloud |

## Self-host

`oidc-bridge.aitc.dev` 공용 인스턴스는 rate-limited이며 SLA 없는 best-effort입니다. 보안이 민감한 워크로드는 self-host를 권장합니다. [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md)에서 `bootstrap` + `doctor` 기반 셋업 가이드를 확인하세요.

## 라이선스

BSD-3-Clause. `LICENSE` 참조.

---

커뮤니티 오픈소스 프로젝트입니다.
