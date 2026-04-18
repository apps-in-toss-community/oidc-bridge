# CLAUDE.md

## 프로젝트 성격 (중요)

**`apps-in-toss-community`는 비공식(unofficial) 오픈소스 커뮤니티다.** 토스 팀과 제휴 없음. 사용자에게 보이는 산출물에서 "공식/official/토스가 제공하는/powered by Toss" 등 제휴·후원·인증 암시 표현을 **쓰지 않는다**. 대신 "커뮤니티/오픈소스/비공식"을 사용한다. 의심스러우면 빼라.

특히 공용 인스턴스를 운영할 때 **rate-limited, best-effort, community-operated**임을 명시. production용 보증 없음.

## 짝 repo

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

## Status

placeholder 상태. 구현 전.

전체 로드맵은 [landing page](https://apps-in-toss-community.github.io/) 참고.
