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

공용 인스턴스(rate-limited, best-effort)가 제공될 예정이며, self-host도 지원 목표.

## Status

See the [organization landing page](https://apps-in-toss-community.github.io/) for the full roadmap.
