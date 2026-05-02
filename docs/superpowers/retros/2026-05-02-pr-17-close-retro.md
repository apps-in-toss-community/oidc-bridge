# PR #17 close retro — when to throw away a feature branch

**Date**: 2026-05-02
**Scope**: Close decision for [PR #17](https://github.com/apps-in-toss-community/oidc-bridge/pull/17) — `feat: M1 — multi-tenant OIDC + mTLS proxy (replaces /verify)`. Branch `m1-oidc-mtls-proxy`, 132 tests green, fully implemented per its own design — but its design was superseded mid-flight.
**Author**: Claude session that closed the PR with rationale comment, deleted the branch, and pruned the local tracking ref.

This sits next to `2026-05-02-phase-01-retro.md`. That file captures stories about *executing a plan well*; this one captures the story of *deciding a plan was wrong* and acting on that.

---

## What PR #17 actually was

PR #17 implemented the **M1-redesign spec** — a parallel design effort that ran before the zero-code mode design landed. It shipped:

- **File-based multi-tenant store** with `tenant create / list / delete` CLI and an `--offline` bootstrap mode. Default backend: filesystem JSON; alternate: `GCPSM` (lazily loaded GCP Secret Manager) for the entire tenant store.
- **`/oidc/*` surface** — discovery, JWKS, token, userinfo, revoke. Public-client only.
- **mTLS Toss adapter** with sealed `aitc_*` access tokens (per-tenant HKDF + AES-256-GCM).
- Removed the legacy `/verify` endpoint and `TOSS_CLIENT_ID/SECRET` env. Added a `MIGRATION.md`.
- **132 tests**, all green. Discovery + JWKS + CLI smoke confirmed. The PR was effectively done.

The PR was opened against `main` and sat reviewable for ~24 hours.

## What changed underneath it

While PR #17 was open, we ran the brainstorming + spec process for "zero-code mode" (the design currently in `docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md`). That spec replaced enough of M1's structural choices that a side-by-side merge would not be possible:

| Concern | M1-redesign (PR #17) | zero-code mode (current main) |
|---|---|---|
| Tenancy model | flat tenants in a file/JSON store | DB-backed `workspaces → apps` two-level, 7 tables |
| Sealed-token prefix | `aitc_*` | `ait_*` |
| Admin model | bash-installed CLI with `tenant *` subcommands, file-based config | DB-backed admin REST + commander CLI with `workspace`/`app`/`api-token` subcommands, API-token auth |
| mTLS material storage | per-tenant disk file referenced by path | `bytea` column on `apps`, sealed with per-app HKDF (`ait/mtls/v1` info) |
| GCP role | "tenant store backend" (full data plane via GCPSM) | "master-key provider" only; data plane stays in pg/sqlite |
| Confidential client | not modeled | `client_secret_basic`/`client_secret_post`, separate from public client |
| Public-client auth | `Origin` allowlist on `/oidc/token` | same — this is the one piece the two designs agreed on |

The two designs share a goal (Toss → OIDC bridge) and even a shape (`/oidc/token` against mTLS Toss), but the **data plane and admin model are incompatible**. There is no clean rebase: most of PR #17's source files would need to be rewritten against the new schema and admin surface.

## The decision

Two options:

1. **Rebase + adapt** PR #17 onto the new design. Estimated effort: high — most files would change substantially. Risk: a slow, error-prone rewrite where the test suite (which is the only thing keeping the rewrite honest) gets gutted along with the source. The end state is a new PR that happens to share author history with #17 but no longer ships anything from #17.
2. **Close PR #17 as superseded**, salvage concepts (mTLS adapter shape, RS256 + JWKS + multi-`kid`, sealed-envelope idea) into the new design, reuse zero **lines of code**, and execute zero-code mode as a clean phase sequence (Phase 0 → 1 → 2 → 3 …).

We chose option 2. PR #17 was closed with a comment naming the supersession, the local + remote `m1-oidc-mtls-proxy` branches deleted, and the stale remote tracking ref pruned. No commits were cherry-picked.

## Why option 2 was right (and the signal that told us so)

The earliest cheap signal that PR #17 was on the wrong axis was the **prefix conflict** (`aitc_*` vs `ait_*`). At the surface level it's a one-character cosmetic disagreement. Underneath, it's a flag: the two designs disagree about what a Bridge access token *is* — M1 thought it was a per-tenant resource (so the prefix mirrors the org name), zero-code mode thinks it's a per-app resource bound by HKDF info to a specific app's sealing key (so the prefix is generic, the binding is in the AAD).

Once the disagreement reaches the "what is this thing, conceptually" layer, mechanical rebase is no longer recoverable. The structural divergence we listed in the table above is just downstream consequence.

**The lesson is not "kill long-lived branches" — it's "watch for the disagreement at the conceptual layer, not just the API layer."** A 132-test PR feels like sunk cost; it isn't. The cost was already sunk before the PR was even written, the moment the design pivoted. Closing the PR is the lowest-cost action available now, not a write-off of the prior work.

## What we kept

Nothing was reused from #17's *code*. From its *design and prose* we kept:

- **mTLS adapter contract shape** — Bridge calls Toss via `undici` over a per-app `https.Agent`. zero-code mode keeps this; Phase 5 implements it in real form.
- **OIDC discovery surface (omitting `authorization_endpoint`)** — same shape ships in zero-code mode Phase 3 plan, [§5.7 of the design spec](../specs/2026-05-01-oidc-bridge-zero-code-mode-design.md).
- **Sealed-envelope idea (per-key HKDF + AES-256-GCM + version prefix)** — kept, with a tighter binding (AAD includes `app_id, toss_user_key, sealing_key_version`).
- **Removal of `/verify` and `TOSS_CLIENT_ID/SECRET`** — already shipped in Phase 0.

The `MIGRATION.md` PR #17 introduced was kept verbatim — it describes the M0 → zero-code mode transition correctly, so we did not regenerate it.

## Process note: timing of the close

We closed PR #17 *after* Phase 0/1/2 were on `main`. In hindsight, the close could have happened earlier (the moment the zero-code mode spec was approved). We left it open partly out of caution — the implementation phases of zero-code mode could in principle have hit a wall that forced a fallback to the M1 design. They didn't. By the time PRs #19, #20, #21 were merged, PR #17 was unambiguously redundant.

The cost of the delay was zero: no one merged it, no one tried to rebase it, no agent spent compute looking at it. The main downside of leaving a stale PR open is *attention noise* (it shows up in `gh pr list`); we paid that cost for ~24 hours.

**Lesson:** when superseding a long-lived branch, name the supersession in the new spec the moment it lands ("This replaces the M1 design at PR #17"). Then either close PR #17 immediately, or set a tripwire — "close PR #17 the moment Phase N of the new plan merges" — so the close doesn't get forgotten in the new work.

## Carryover

Things future supersession decisions should keep in mind:

1. **Disagreements at the conceptual layer** (token prefix, ownership model, what a "tenant" is) are not surface-level naming bikeshed — they are structural disagreement showing through. Treat them as a tripwire.
2. **A green test suite is not evidence of correctness when the spec underneath has changed.** PR #17 had 132 green tests. The tests proved the code matched *its own spec*, not *the spec we wanted*.
3. **Reuse design, not code, when superseding.** Cherry-picking commits across a structural rewrite is more expensive than rewriting from the new spec — and produces inferior results because the old commits encode old assumptions.
4. **Plans authored ahead of their dependency phase need re-audit at dependency-merge time.** The Phase 03 plan was written against design assumptions that Phase 2 ultimately did not match (see `docs/superpowers/plans/2026-05-01-zero-code-phase-03-amendments.md` for the four blockers we caught). Same shape as the PR #17 problem at a smaller scale.
5. **Close-with-rationale, then delete.** A PR closed without explanation looks abandoned. A PR closed with a comment naming what superseded it (with links) is documentation. Cost: 5 minutes. Value: future readers (humans or agents) can reconstruct the decision.
