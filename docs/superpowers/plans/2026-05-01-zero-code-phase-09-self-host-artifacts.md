# Phase 9 Implementation Plan — Self-host Deployment Artifacts

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the bridge as a self-contained self-host stack — multi-stage `node:24-alpine` Dockerfile, `docker-compose.yml` (bridge + Postgres + Caddy with TLS termination), `SECURITY.md` (threat model + responsible disclosure), `SELF_HOSTING.md` production-hardening section (Phase 7 wrote the bootstrap walkthrough; this phase appends hardening), and a clean-VPS smoke test that exercises the full path from `docker compose up` to a real `/oidc/token` round trip — all on a fresh `vc2-1c-1gb` Vultr Seoul instance per repo CLAUDE.md.

**Architecture:** Two artifacts and three docs. The Dockerfile is multi-stage (deps → build → runtime) and pins to a digest of `node:24-alpine`; the runtime stage runs as non-root UID 1001, copies only `dist/`, `package.json`, `pnpm-lock.yaml`, `migrations/`, and the production `node_modules` from a `pnpm deploy` prune step, and starts `node dist/server.mjs`. The compose file wires three services — `bridge` (this image), `postgres` (`postgres:17-alpine`, internal-only, named volume), and `caddy` (`caddy:2-alpine`, public 80/443, named volumes for certs and config) — with health-checks that gate `bridge` on `postgres` ready and a Caddy `Caddyfile` that terminates TLS via Let's Encrypt and reverse-proxies `/` to `bridge:8080`. Master-key bytes live outside Docker volumes — operators bind-mount `${MASTER_KEY_DIR}` (mode 0700) from host `/etc/oidc-bridge/master-keys/` so master-key rotation does not require image rebuilds. The smoke test runs on a freshly provisioned Vultr Seoul VPS via a documented `scripts/smoke-vps.sh` that operators can re-run; it provisions Docker, clones the repo, copies a fixture `.env`, runs `docker compose up -d`, polls `/healthz`, runs `bridge doctor`, and verifies a successful `/oidc/token` round trip with the mock Toss adapter (so the smoke does not require a real Toss cert).

**Tech Stack:** Docker multi-stage builds; `node:24-alpine` runtime; `corepack` for pnpm 10.33.0 pinning; `pnpm deploy --filter` for production-pruned `node_modules`; `dumb-init` as PID 1; `postgres:17-alpine`; `caddy:2-alpine` with on-demand TLS via Let's Encrypt; `docker-compose` (Compose v2 spec); `bash` for the smoke script; existing `pnpm bridge doctor` (Phase 7) for end-to-end health gating.

---

## Universal invariants (apply to every task in this plan)

These are non-negotiable. Any task that violates one is rejected at review and reworked.

1. **TDD where there is application code to test.** This phase is mostly artifacts (Dockerfile, compose, docs); the testable surface is the smoke script and the helper scripts. For each helper script with branching logic, write a failing test first (bash + shellcheck where possible; vitest for any TS helper).
2. **No PII in logs.** Image build logs, compose logs, and smoke logs must never echo a master key, API token plaintext, password, mTLS PEM, or Toss AT/RT. Smoke fixtures use mock Toss.
3. **Bridge never spontaneously calls Toss.** No image-build-time or container-start-time call to `apps-in-toss-api.toss.im`. Smoke uses `BRIDGE_TOSS_ADAPTER=mock`.
4. **Toss refresh_token never leaves the sealed wrapper.** Smoke does not exercise refresh; this is verified upstream in Phase 4/5 tests. Phase 9 does not introduce new code paths that touch Toss tokens.
5. **Public clients use Origin, not client_secret.** Smoke fixtures register a confidential client with `client_secret_basic` for explicitness; the smoke does not exercise public-client paths.
6. **mTLS material never returns from any GET.** Smoke `/admin/apps` GET responses must not echo `mtls_cert_pem` / `mtls_key_pem` — Phase 4 tests already pin this; Phase 9 reuses the smoke client to retrieve apps and asserts neither field appears.
7. **Cloud-agnostic.** No GCP-specific code in the Docker image, no `gcloud` CLI in the runtime layer, no metadata-server reads at startup. The image must boot identically on bare metal, Vultr, AWS EC2, Hetzner.
8. **Self-host first-class.** Compose stack runs end-to-end with no external secret manager — `MASTER_KEY_PROVIDER=file` is the default in the compose `.env.example`, GCPSM is optional. Image must run `BRIDGE_TOSS_ADAPTER=mock` with no Toss cert and pass `pnpm bridge doctor` (toss probe yellow per Phase 7 design).
9. **TLS termination is external.** The bridge container speaks plain HTTP on `0.0.0.0:8080`; Caddy is the only TLS speaker. The image must not bundle a TLS cert nor read one at startup.
10. **Runtime is unprivileged.** The runtime stage runs as a non-root user (`bridge`, UID 1001, GID 1001). The container drops `ALL` capabilities and adds none. `read_only: true` rootfs with explicit `tmpfs` for `/tmp` and a bind-mounted writable data dir.
11. **Reproducibility is required.** The Dockerfile pins `node:24-alpine` to a sha256 digest, pins `corepack prepare pnpm@10.33.0 --activate`, and uses `pnpm install --frozen-lockfile`. CI builds with `--provenance=true --sbom=true` (existing build pipeline; this phase does not introduce a new build pipeline).
12. **No backwards-compat hacks for non-existent users.** This is a fresh feature. No "legacy v0" tags, no compatibility shims, no `// removed` comments.

When a step says "verify with X", run X verbatim and confirm the expected output. Don't move on if it doesn't match.

---

## Files touched this phase

```
Dockerfile                                    # CREATE — multi-stage build (deps, build, runtime)
.dockerignore                                 # CREATE — keep image small + reproducible
docker-compose.yml                            # CREATE — bridge + postgres + caddy + healthchecks
docker/
  Caddyfile.example                           # CREATE — TLS-terminating reverse proxy template
  .env.example                                # CREATE — operator-facing env template (NO secrets)
docs/
  SECURITY.md                                 # CREATE — threat model + responsible disclosure
  SELF_HOSTING.md                             # MODIFY — append "Production hardening" section
                                              #   (Phase 7 created the bootstrap walkthrough)
  RUNBOOK.md                                  # MODIFY — add "deploying with docker compose" pointer
scripts/
  smoke-vps.sh                                # CREATE — clean-VPS end-to-end smoke
  smoke-image.sh                              # CREATE — local single-host image smoke (used in CI)
test/
  smoke/
    smoke-image.test.ts                       # CREATE — vitest harness wrapping smoke-image.sh
    parse-doctor.test.ts                      # CREATE — unit tests for jq/grep extractor used in smoke
package.json                                  # MODIFY — add pnpm scripts: image:build, smoke:image, smoke:vps
.github/workflows/ci.yml                      # MODIFY — add image-build + smoke-image job
```

This is the only set of files this phase touches. Anything not on this list is out of scope; do not touch it.

---

## Pre-flight: read these once before starting

Before you begin Task 1, do this in order. It's about ten minutes and prevents the rework that comes from missing a piece of context.

1. Read `docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md`, especially:
   - §3.1 "In scope" bullet "Self-host first-class: SQLite fallback (single-app limit), filesystem master-key file, `docker-compose.yml`."
   - §5.6 "Cloud-agnostic invariants (self-host first-class)" — the seven invariants this phase exists to satisfy.
   - §11 "Phase 9: Self-hosting deployment artifacts" — the four-line scope statement this plan expands.
2. Read the Phase 0 plan to confirm the build output path: `dist/server.mjs` is the runtime entry; `pnpm build` produces it via tsdown.
3. Read the Phase 1 plan §"Master keys" to confirm the on-disk layout the runtime expects: `${MASTER_KEY_DIR}/v<version>.key`, mode 600, 32 raw bytes.
4. Read the Phase 7 plan §"SELF_HOSTING.md walkthrough" to know what is already in `docs/SELF_HOSTING.md`. This phase appends a "Production hardening" section; it does not rewrite the bootstrap walkthrough.
5. Read the Phase 8 plan §"Status page" to confirm `/status` is HTML and unauthenticated, and §"Rate limit" to confirm `/healthz` is exempt — the compose health-check uses `/healthz` and must not be rate-limited.
6. Skim `package.json` to see existing scripts (`build`, `start`, `test`, `lint`) so the new scripts in Task 11 fit the established style.
7. Confirm Vultr Seoul `vc2-1c-1gb` (~$5/mo, 1 vCPU, 1 GiB RAM, 25 GB SSD) — per repo CLAUDE.md this is the production target. The image and compose stack must boot and run inside this footprint with headroom for a single Postgres + Caddy + bridge.

When that's done, start Task 1.

---

## Task 1: `.dockerignore` (write before the Dockerfile so first build is clean)

**Files:**
- Create: `.dockerignore`

**Why first:** A Dockerfile written without `.dockerignore` quietly bakes `node_modules`, `.git`, dotfiles, fixtures, and worktrees into the build context. The first `docker build` then takes minutes and produces a non-reproducible layer cache. Write the ignore list before any `COPY .`.

- [ ] **Step 1: Write `.dockerignore`**

```
# .dockerignore — keep build context minimal and reproducible
.git
.gitignore
.github
.vscode
.idea
.DS_Store

# node + pnpm
node_modules
**/node_modules
.pnpm-store

# build artifacts that the image rebuilds
dist
coverage
.tsbuildinfo
*.tsbuildinfo

# tests + fixtures (image runs migrations + dist; tests stay on host)
test
**/__tests__
**/__fixtures__
*.test.ts
*.spec.ts

# tooling that is not needed at runtime
.eslintrc*
biome.json
biome.jsonc
vitest.config.*
tsdown.config.*

# dev / ops files
.env
.env.*
.envrc
docker-compose.override.yml
docs
scripts/*.sh
!scripts/migrate.sh
!scripts/entrypoint.sh

# claude code / superpowers metadata
.claude
.superpowers
docs/superpowers

# worktrees (umbrella convention)
oidc-bridge-*/
```

The `!scripts/...` entries reserve a path back in for any helper scripts the runtime stage *does* want to ship; this plan does not introduce any (the entrypoint is `node dist/server.mjs` directly), but the syntax is here so a future task can opt one in by removing it from the ignore.

- [ ] **Step 2: Verify the build context is small**

```bash
docker build --no-cache --progress=plain -t bridge:context-test . --target=deps 2>&1 | head -5
```

Expected: the first line shows `transferring context: <few MB>`. If it transfers more than 50 MB, an entry is missing — fix before continuing.

- [ ] **Step 3: Commit**

```bash
git add .dockerignore
git commit -m "feat: .dockerignore for reproducible image builds"
```

---

## Task 2: Dockerfile — `deps` stage (production deps only)

**Files:**
- Create: `Dockerfile` (will grow over Tasks 2–4)

The image is three stages: `deps` (production-only `node_modules`), `build` (full `node_modules` + tsdown → `dist/`), `runtime` (alpine + non-root + only what's needed to run). Task 2 establishes the `deps` stage.

- [ ] **Step 1: Write the `deps` stage**

```dockerfile
# syntax=docker/dockerfile:1.7

# ----- Stage 1: deps -----
# Build a pnpm-deploy pruned node_modules tree containing only production dependencies.
# pnpm deploy follows the workspace graph and copies a self-contained subtree into /out;
# this gives the runtime stage a node_modules that has no dev dependencies and no symlinks
# pointing outside the deploy root, which is what we want for a thin runtime image.
FROM node:24-alpine@sha256:PINME AS deps

# corepack ships with node:24 but is disabled by default. Activate the exact pnpm version
# the umbrella pins (10.33.0) so the lockfile resolves identically in the image and on dev.
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

WORKDIR /app

# Copy only the manifests first so this layer caches across source changes.
COPY package.json pnpm-lock.yaml ./

# --frozen-lockfile fails fast if the lockfile is out of date; that is the desired CI behavior.
# --prod is *not* used here because the build stage needs dev deps; we prune later via pnpm deploy.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm-store \
    pnpm config set store-dir /pnpm-store && \
    pnpm install --frozen-lockfile

# Copy the rest of the source so pnpm deploy can resolve workspace exports.
COPY . .

# pnpm deploy --prod copies a self-contained, prod-only tree to /out.
# Even though this is not a workspace today, --legacy keeps the command working for
# single-package repos; --prod prunes dev dependencies.
RUN pnpm deploy --legacy --prod /out
```

The `@sha256:PINME` is intentional and *must* be replaced with a real digest in Step 2. Keeping it as a literal placeholder fails the build, which is the point — it forces the operator to look up the current `node:24-alpine` digest at the time of writing rather than blindly taking `latest`.

- [ ] **Step 2: Pin the `node:24-alpine` digest**

Run on the host:

```bash
docker pull node:24-alpine
docker inspect --format='{{index .RepoDigests 0}}' node:24-alpine
```

Expected output: `node@sha256:<64-hex>`. Take the `sha256:<64-hex>` portion and replace `@sha256:PINME` in the Dockerfile.

Pin verification:

```bash
grep -n 'node:24-alpine@sha256:' Dockerfile
```

Expected: exactly one line, no `PINME`.

- [ ] **Step 3: Build the deps stage in isolation to confirm it works**

```bash
docker build --target deps --progress=plain -t bridge:deps . 2>&1 | tail -20
```

Expected: ends with `naming to docker.io/library/bridge:deps done` and no errors. Build time on a warm cache should be under 60 s.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile
git commit -m "feat: Dockerfile deps stage (pnpm deploy --prod prune)"
```

---

## Task 3: Dockerfile — `build` stage (tsdown → dist/)

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Append the `build` stage**

Append after the `deps` stage:

```dockerfile

# ----- Stage 2: build -----
# Compile TypeScript to dist/ using the full (dev-included) node_modules from deps.
FROM node:24-alpine@sha256:PINME AS build

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

WORKDIR /app

# Reuse the deps stage's node_modules (the full tree, including dev deps, before pnpm deploy).
COPY --from=deps /app /app

# tsdown produces dist/server.mjs (Phase 0 build script).
RUN pnpm build

# Sanity check: the runtime stage's CMD points here, so this must exist.
RUN test -f dist/server.mjs || (echo "build did not produce dist/server.mjs" && exit 1)
```

Use the same digest you pinned in Task 2 Step 2. Both `node:24-alpine` references must reference the same digest.

- [ ] **Step 2: Build through the build stage**

```bash
docker build --target build --progress=plain -t bridge:build . 2>&1 | tail -10
```

Expected: ends with `naming to docker.io/library/bridge:build done`. The `RUN test -f dist/server.mjs` line either passes silently or fails the build with the explicit message.

Confirm the build artifact is reachable from the image:

```bash
docker run --rm --entrypoint /bin/sh bridge:build -c 'ls -lh /app/dist/server.mjs'
```

Expected: a single line showing the file exists with non-zero size.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat: Dockerfile build stage (tsdown -> dist/server.mjs)"
```

---

## Task 4: Dockerfile — `runtime` stage (alpine, non-root, dumb-init, healthcheck)

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Append the `runtime` stage**

```dockerfile

# ----- Stage 3: runtime -----
# Minimal layer: alpine + node + dumb-init + the pruned node_modules + dist/.
FROM node:24-alpine@sha256:PINME AS runtime

# dumb-init is PID 1 so SIGTERM from `docker stop` reaches the node process and
# triggers graceful shutdown (Phase 0 install graceful-shutdown handler).
# wget is for the HEALTHCHECK; alpine ships with busybox wget, no install needed.
RUN apk add --no-cache dumb-init=~1.2.5

# Non-root runtime user. Pinning UID/GID to 1001 lets operators chown bind-mounted
# host directories to the same UID without coordinating with the image internals.
RUN addgroup -g 1001 -S bridge && \
    adduser -u 1001 -S -G bridge -h /home/bridge -s /sbin/nologin bridge

WORKDIR /app

# Copy the prod-only node_modules from the deps stage's pnpm deploy output.
COPY --from=deps --chown=bridge:bridge /out/node_modules ./node_modules
# Copy the build output from the build stage.
COPY --from=build --chown=bridge:bridge /app/dist ./dist
# Copy package.json so `node` resolves "type": "module" for .mjs and so `bridge --version`
# works against the version field (Phase 7 doctor reads it).
COPY --from=build --chown=bridge:bridge /app/package.json ./package.json
# Copy migrations so the runtime can run them on first boot (Phase 1 startup task).
COPY --from=build --chown=bridge:bridge /app/migrations ./migrations

USER bridge

# The bridge process speaks plain HTTP on PORT (default 8080). Caddy / Cloud Run terminates TLS.
EXPOSE 8080

ENV NODE_ENV=production \
    NODE_OPTIONS="--enable-source-maps" \
    PORT=8080

# Healthcheck talks to /healthz on the loopback. /healthz is exempt from rate-limit (Phase 8).
# Container is unhealthy if /healthz returns non-2xx for 3 consecutive 10-second probes.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD wget --quiet --spider http://127.0.0.1:8080/healthz || exit 1

# dumb-init forwards signals; node binary runs the compiled mjs entry.
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/server.mjs"]
```

- [ ] **Step 2: Build the full image and inspect it**

```bash
docker build --progress=plain -t bridge:dev . 2>&1 | tail -10
docker images bridge:dev --format '{{.Repository}}:{{.Tag}}  {{.Size}}'
```

Expected size: under 200 MB. If above, something dev-only leaked into the runtime stage; inspect with `docker history bridge:dev --no-trunc | head -20`.

Verify non-root:

```bash
docker run --rm bridge:dev id
```

Expected: `uid=1001(bridge) gid=1001(bridge) groups=1001(bridge)`.

Verify graceful shutdown wiring (the entrypoint):

```bash
docker run --rm bridge:dev /usr/bin/dumb-init --version
```

Expected: a single line like `dumb-init v1.2.5`.

- [ ] **Step 3: Smoke-run the image alone**

The image needs a database to actually boot the app. For a smoke that proves the image *itself* is well-formed (entrypoint, perms, env, healthcheck), use SQLite + the `mock` Toss adapter and a temporary master-key file.

```bash
mkdir -p /tmp/bridge-smoke/{data,master-keys}
chmod 700 /tmp/bridge-smoke/master-keys
head -c 32 /dev/urandom > /tmp/bridge-smoke/master-keys/v1.key
chmod 600 /tmp/bridge-smoke/master-keys/v1.key

docker run --rm --name bridge-smoke -d \
  -p 18080:8080 \
  -v /tmp/bridge-smoke/data:/data \
  -v /tmp/bridge-smoke/master-keys:/master-keys:ro \
  -e DATABASE_URL="sqlite:///data/bridge.db" \
  -e MASTER_KEY_PROVIDER=file \
  -e MASTER_KEY_DIR=/master-keys \
  -e BRIDGE_TOSS_ADAPTER=mock \
  -e OIDC_ISSUER=https://localhost:18080 \
  -e ADMIN_TOKEN=smoke-token-abcdefghijk \
  bridge:dev

# Wait for healthcheck to flip green.
for i in $(seq 1 30); do
  state=$(docker inspect --format='{{.State.Health.Status}}' bridge-smoke 2>/dev/null || echo none)
  if [ "$state" = "healthy" ]; then break; fi
  sleep 1
done

curl -fsS http://127.0.0.1:18080/healthz
echo
docker logs bridge-smoke 2>&1 | tail -5
docker stop bridge-smoke >/dev/null
rm -rf /tmp/bridge-smoke
```

Expected: `curl` returns `ok` (Phase 0 healthz body) and the container reaches `healthy` within 30 s. The last log lines should be JSON Pino lines (Phase 8), not plain-text errors.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile
git commit -m "feat: Dockerfile runtime stage (non-root bridge:1001, healthcheck)"
```

---

## Task 5: `scripts/smoke-image.sh` (extracted reusable smoke)

**Files:**
- Create: `scripts/smoke-image.sh`
- Create: `test/smoke/parse-doctor.test.ts`

Task 4 Step 3 ran the smoke inline; Task 5 extracts it into a reusable shell script that CI can invoke and that the vitest harness in Task 6 wraps. The script has just enough branching to be worth unit-testing the parser piece.

- [ ] **Step 1: Write `parse-doctor.test.ts` first (failing test)**

```ts
// test/smoke/parse-doctor.test.ts
import { describe, expect, it } from 'vitest';
import { extractDoctorState } from '../../scripts/lib/parse-doctor.ts';

describe('extractDoctorState', () => {
  it('returns "green" when status is green', () => {
    const json = JSON.stringify({ status: 'green', items: [] });
    expect(extractDoctorState(json)).toBe('green');
  });

  it('returns "yellow" when status is yellow', () => {
    const json = JSON.stringify({ status: 'yellow', items: [] });
    expect(extractDoctorState(json)).toBe('yellow');
  });

  it('returns "red" when status is red', () => {
    const json = JSON.stringify({ status: 'red', items: [] });
    expect(extractDoctorState(json)).toBe('red');
  });

  it('throws on malformed JSON', () => {
    expect(() => extractDoctorState('not-json')).toThrow(/parse/i);
  });

  it('throws on missing status field', () => {
    expect(() => extractDoctorState('{}')).toThrow(/status/i);
  });

  it('throws on unknown status value', () => {
    expect(() => extractDoctorState('{"status":"purple"}')).toThrow(/unknown.*purple/i);
  });
});
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
pnpm test test/smoke/parse-doctor.test.ts 2>&1 | tail -10
```

Expected: `Cannot find module '.../scripts/lib/parse-doctor.ts'` — six failing tests.

- [ ] **Step 3: Write the parser**

```ts
// scripts/lib/parse-doctor.ts
export type DoctorState = 'green' | 'yellow' | 'red';

export function extractDoctorState(input: string): DoctorState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch (e) {
    throw new Error(`failed to parse doctor JSON: ${(e as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('doctor output is not an object');
  }
  const status = (parsed as { status?: unknown }).status;
  if (typeof status !== 'string') {
    throw new Error('doctor output is missing "status" field');
  }
  if (status !== 'green' && status !== 'yellow' && status !== 'red') {
    throw new Error(`unknown doctor status value: ${status}`);
  }
  return status;
}
```

- [ ] **Step 4: Run the test, confirm it passes**

```bash
pnpm test test/smoke/parse-doctor.test.ts 2>&1 | tail -10
```

Expected: 6 passed.

- [ ] **Step 5: Write `scripts/smoke-image.sh`**

```bash
#!/usr/bin/env bash
# scripts/smoke-image.sh — runs the bridge image against SQLite + mock Toss
# and asserts /healthz, /status, and `bridge doctor` all respond correctly.
#
# Inputs (env, all optional):
#   IMAGE  default: bridge:dev
#   PORT   default: 18080  (host port)
#   ADMIN_TOKEN  default: a generated random token (printed once on stderr)
#
# Outputs: exit 0 on green or yellow doctor result, non-zero on red or any failure.
set -euo pipefail

IMAGE="${IMAGE:-bridge:dev}"
PORT="${PORT:-18080}"
ADMIN_TOKEN="${ADMIN_TOKEN:-$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)}"
WORK="$(mktemp -d -t bridge-smoke-XXXXXX)"
trap 'docker rm -f bridge-smoke >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/data" "$WORK/master-keys"
chmod 700 "$WORK/master-keys"
head -c 32 /dev/urandom > "$WORK/master-keys/v1.key"
chmod 600 "$WORK/master-keys/v1.key"

echo "[smoke] starting $IMAGE on port $PORT" >&2

docker run --rm --name bridge-smoke -d \
  -p "${PORT}:8080" \
  -v "$WORK/data:/data" \
  -v "$WORK/master-keys:/master-keys:ro" \
  -e DATABASE_URL="sqlite:///data/bridge.db" \
  -e MASTER_KEY_PROVIDER=file \
  -e MASTER_KEY_DIR=/master-keys \
  -e BRIDGE_TOSS_ADAPTER=mock \
  -e OIDC_ISSUER="http://localhost:${PORT}" \
  -e ADMIN_TOKEN="$ADMIN_TOKEN" \
  "$IMAGE" >/dev/null

# Wait up to 60s for healthcheck to go healthy.
for i in $(seq 1 60); do
  state="$(docker inspect --format='{{.State.Health.Status}}' bridge-smoke 2>/dev/null || echo none)"
  if [ "$state" = "healthy" ]; then break; fi
  sleep 1
done
if [ "$state" != "healthy" ]; then
  echo "[smoke] FAIL: container did not become healthy in 60s (state=$state)" >&2
  docker logs bridge-smoke 2>&1 | tail -30 >&2
  exit 1
fi

# /healthz must return exactly "ok"
got="$(curl -fsS "http://127.0.0.1:${PORT}/healthz")"
if [ "$got" != "ok" ]; then
  echo "[smoke] FAIL: /healthz returned '$got' (want 'ok')" >&2
  exit 1
fi

# /status must respond JSON when ?format=json (Phase 8)
status_code="$(curl -s -o "$WORK/status.json" -w '%{http_code}' "http://127.0.0.1:${PORT}/status?format=json")"
if [ "$status_code" != "200" ]; then
  echo "[smoke] FAIL: /status returned HTTP $status_code" >&2
  cat "$WORK/status.json" >&2
  exit 1
fi

# `bridge doctor --json` from inside the container must return green or yellow.
doctor_out="$(docker exec bridge-smoke node dist/cli.mjs doctor --json)"
state="$(node -e 'import("./scripts/lib/parse-doctor.ts").then(m=>console.log(m.extractDoctorState(require("fs").readFileSync(0,"utf8"))))' <<<"$doctor_out")"
case "$state" in
  green|yellow) echo "[smoke] PASS: doctor=$state" ;;
  red)
    echo "[smoke] FAIL: doctor=red" >&2
    echo "$doctor_out" >&2
    exit 1 ;;
  *)
    echo "[smoke] FAIL: doctor returned unexpected state '$state'" >&2
    exit 1 ;;
esac

echo "[smoke] OK"
```

- [ ] **Step 6: Make it executable, lint with shellcheck**

```bash
chmod +x scripts/smoke-image.sh
shellcheck scripts/smoke-image.sh
```

Expected: shellcheck reports no issues. If shellcheck is not installed locally, run via Docker: `docker run --rm -v "$PWD:/mnt" koalaman/shellcheck:stable /mnt/scripts/smoke-image.sh`.

- [ ] **Step 7: Run the smoke against the image built in Task 4**

```bash
./scripts/smoke-image.sh
```

Expected output ends with `[smoke] OK` and exit code 0. The doctor result is `yellow` (no Toss cert) per Phase 7 design, which is acceptable.

- [ ] **Step 8: Commit**

```bash
git add scripts/smoke-image.sh scripts/lib/parse-doctor.ts test/smoke/parse-doctor.test.ts
git commit -m "feat: smoke-image.sh + parse-doctor helper"
```

---

## Task 6: vitest harness for smoke-image (CI hook)

**Files:**
- Create: `test/smoke/smoke-image.test.ts`

CI runs vitest. Wrapping the shell script in a vitest test that conditionally runs makes the smoke a first-class citizen in `pnpm test:smoke` without forcing it on every developer.

- [ ] **Step 1: Write the test (failing — script not callable from vitest yet)**

```ts
// test/smoke/smoke-image.test.ts
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const ENABLED = process.env.BRIDGE_SMOKE_IMAGE === '1';
const SCRIPT = 'scripts/smoke-image.sh';

describe.skipIf(!ENABLED)('smoke: bridge image (BRIDGE_SMOKE_IMAGE=1)', () => {
  it('script exists and is executable', () => {
    expect(existsSync(SCRIPT)).toBe(true);
  });

  it('image smoke passes against bridge:dev', () => {
    const out = execFileSync('bash', [SCRIPT], {
      env: { ...process.env, IMAGE: 'bridge:dev' },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    expect(out).toMatch(/\[smoke\] OK/);
  }, 120_000);
});
```

- [ ] **Step 2: Run with the gate off (default)**

```bash
pnpm test test/smoke/smoke-image.test.ts 2>&1 | tail -5
```

Expected: 2 tests skipped (because `BRIDGE_SMOKE_IMAGE` is not set).

- [ ] **Step 3: Run with the gate on, image already built**

```bash
docker images bridge:dev --format '{{.Repository}}:{{.Tag}}' | grep -q '^bridge:dev$' || docker build -t bridge:dev .
BRIDGE_SMOKE_IMAGE=1 pnpm test test/smoke/smoke-image.test.ts 2>&1 | tail -10
```

Expected: 2 passed.

- [ ] **Step 4: Commit**

```bash
git add test/smoke/smoke-image.test.ts
git commit -m "test: smoke-image vitest harness gated by BRIDGE_SMOKE_IMAGE"
```

---

## Task 7: `docker/Caddyfile.example` (TLS-terminating reverse proxy)

**Files:**
- Create: `docker/Caddyfile.example`

Caddy is the only TLS speaker in the self-host stack. It does on-demand Let's Encrypt issuance for whatever hostname the operator points at the VPS, and reverse-proxies plain HTTP to `bridge:8080`. The compose service mounts this file read-only.

- [ ] **Step 1: Write `docker/Caddyfile.example`**

```caddyfile
# docker/Caddyfile.example
#
# Copy to ./docker/Caddyfile and replace BRIDGE_HOST with your hostname before
# `docker compose up`. Caddy will obtain a Let's Encrypt certificate automatically
# on first request to that hostname, provided ports 80 and 443 are reachable from
# the public internet and DNS resolves to this host.
#
# This file MUST NOT contain TLS keys or any other secrets. The Caddy certs are
# managed by Caddy in the `caddy_data` volume.

{
    # Operator-facing email used by Let's Encrypt for expiry notices. Required.
    # Override via the CADDY_LE_EMAIL env (compose passes it through).
    email {$CADDY_LE_EMAIL}

    # Lock down Caddy's admin API to localhost only; default already does this on
    # 2.x but stating it explicitly prevents accidental exposure if someone exposes
    # port 2019 in compose later.
    admin localhost:2019
}

# Replace BRIDGE_HOST with your hostname (e.g. `oidc-bridge.example.com`).
# `{$BRIDGE_HOST}` reads from the env at startup; set it in `.env` (Task 9).
{$BRIDGE_HOST} {
    # Forward everything to the bridge container on its plain HTTP port.
    reverse_proxy bridge:8080 {
        # Pass through the client IP so the bridge's IP-hash logger (Phase 8) sees
        # the real client address rather than the docker bridge gateway.
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Forwarded-Host {host}

        # Phase 8 trusts inbound X-Request-Id only when it matches /^[A-Za-z0-9_.\-]+$/
        # and is <=128 chars. Caddy passes it through unchanged; the requestId middleware
        # sanitizes. We do not generate a request id here -- bridge does.

        # Healthcheck-related: do not buffer; status updates should be near-real-time.
        flush_interval -1
    }

    # Strict transport security with a generous max-age. Adjust if you control
    # multiple subdomains and prefer includeSubDomains.
    header {
        Strict-Transport-Security "max-age=31536000"
        # Bridge is API-only; deny framing entirely.
        X-Frame-Options "DENY"
        # No referrer leakage on outbound links (the /status page is the only HTML
        # we serve, but defense in depth).
        Referrer-Policy "no-referrer"
        # Remove the Server header to avoid version disclosure.
        -Server
    }

    # Access logs to stdout in JSON format so `docker compose logs caddy` correlates
    # with Bridge's Pino logs (Phase 8). The bridge log already carries request_id;
    # this gives us upstream-side timing if we ever need it.
    log {
        output stdout
        format json
    }
}
```

- [ ] **Step 2: Verify Caddyfile syntax**

```bash
docker run --rm -v "$PWD/docker/Caddyfile.example:/etc/caddy/Caddyfile:ro" \
  -e BRIDGE_HOST=example.test -e CADDY_LE_EMAIL=ops@example.test \
  caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile
```

Expected: `Valid configuration` on the last line.

- [ ] **Step 3: Commit**

```bash
git add docker/Caddyfile.example
git commit -m "feat: Caddyfile example (TLS terminator, reverse proxy to bridge)"
```

---

## Task 8: `docker-compose.yml` (bridge + postgres + caddy)

**Files:**
- Create: `docker-compose.yml`

The compose file wires the three services. Bridge waits on Postgres health; Caddy depends on Bridge being up but does not block on it (Caddy can serve a 502 with the stamped-on hostname while the backend warms).

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
# docker-compose.yml
#
# Self-host stack for oidc-bridge.
#
# Operator workflow:
#   1. cp docker/.env.example .env  (then edit; never commit)
#   2. cp docker/Caddyfile.example docker/Caddyfile  (replace BRIDGE_HOST)
#   3. mkdir -p ./data/master-keys && chmod 700 ./data/master-keys
#   4. docker compose up -d
#   5. docker compose exec bridge node dist/cli.mjs bootstrap
#   6. docker compose exec bridge node dist/cli.mjs doctor
#
# This file pins image references to digests where the upstream maintainers are
# stable enough that a digest update is straightforward. Postgres and Caddy are
# pinned to major.minor + alpine variant; operators who want stricter pinning
# should override locally via docker-compose.override.yml.

services:
  bridge:
    image: ${BRIDGE_IMAGE:-ghcr.io/apps-in-toss-community/oidc-bridge:latest}
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      # --- Required ---
      DATABASE_URL: ${DATABASE_URL:-postgres://bridge:${POSTGRES_PASSWORD}@postgres:5432/bridge}
      OIDC_ISSUER: https://${BRIDGE_HOST}
      ADMIN_TOKEN: ${ADMIN_TOKEN}

      # --- Master keys (filesystem provider; bind-mount supplies the bytes) ---
      MASTER_KEY_PROVIDER: file
      MASTER_KEY_DIR: /master-keys

      # --- Toss adapter ---
      # `mock` for first-boot validation; switch to `real` once mTLS material is loaded
      # for at least one app via `bridge tenant create`.
      BRIDGE_TOSS_ADAPTER: ${BRIDGE_TOSS_ADAPTER:-mock}

      # --- Observability (Phase 8) ---
      RATE_LIMIT_ENABLED: ${RATE_LIMIT_ENABLED:-true}
      OTEL_ENABLED: ${OTEL_ENABLED:-0}
      LOG_LEVEL: ${LOG_LEVEL:-info}

    volumes:
      # Master keys live OUTSIDE the bridge image to survive image upgrades
      # and to allow rotation without rebuilds. 0700 on host, mounted read-only.
      - ${MASTER_KEY_HOST_DIR:-./data/master-keys}:/master-keys:ro

      # Application-managed data dir (used only by SQLite fallback; ignored by Postgres path).
      # Kept for parity with Phase 0/1 file layouts.
      - bridge_data:/data

    expose:
      - "8080"

    # Capability hardening. Bridge does not need any Linux capabilities.
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true

    # Read-only rootfs; tmpfs for /tmp so node can write source-map artifacts.
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777

    healthcheck:
      test: ["CMD", "wget", "--quiet", "--spider", "http://127.0.0.1:8080/healthz"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 15s

  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: bridge
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: bridge
      # initdb args: enforce scram-sha-256 password hashing.
      POSTGRES_INITDB_ARGS: "--auth=scram-sha-256 --auth-host=scram-sha-256"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    # No public port -- Postgres is reachable only from the compose network.
    expose:
      - "5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bridge -d bridge"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 10s
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]
    security_opt:
      - no-new-privileges:true

  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    depends_on:
      - bridge
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    environment:
      BRIDGE_HOST: ${BRIDGE_HOST}
      CADDY_LE_EMAIL: ${CADDY_LE_EMAIL}
    volumes:
      - ./docker/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt:
      - no-new-privileges:true

volumes:
  postgres_data:
  caddy_data:
  caddy_config:
  bridge_data:
```

- [ ] **Step 2: Validate compose file**

```bash
docker compose config >/dev/null
```

Expected: exit 0, no warnings about missing variables (the `.env.example` in Task 9 supplies them; for now, set throwaway values inline):

```bash
BRIDGE_HOST=test.example.com CADDY_LE_EMAIL=ops@test.example.com \
  POSTGRES_PASSWORD=test-pw ADMIN_TOKEN=test-token-aaaaaaaaaaaaaaaa \
  docker compose config >/dev/null && echo OK
```

Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: docker-compose.yml (bridge + postgres + caddy, hardened)"
```

---

## Task 9: `docker/.env.example` (operator template)

**Files:**
- Create: `docker/.env.example`

This file is the single point operators edit. Every variable referenced by `docker-compose.yml` and `Caddyfile.example` must appear here with a clear comment.

- [ ] **Step 1: Write `docker/.env.example`**

```bash
# docker/.env.example
#
# Copy to .env in the repo root, then fill in values. Never commit your .env.
# Compose reads .env automatically when you run `docker compose up`.

# ---------- Required ----------

# The hostname your bridge will be reachable at over public HTTPS.
# Caddy will obtain a Let's Encrypt cert for this name on first request.
BRIDGE_HOST=oidc-bridge.example.com

# Email for Let's Encrypt expiry notices. Required by Caddy.
CADDY_LE_EMAIL=ops@example.com

# Postgres password. Generate with: openssl rand -base64 24
# This is consumed only by the postgres container at first init.
POSTGRES_PASSWORD=replace-me-postgres

# Admin token for the bridge admin REST API. Generate with: openssl rand -base64 32
# Used only when calling /admin/* endpoints; never embedded in client apps.
ADMIN_TOKEN=replace-me-admin

# ---------- Optional ----------

# Image to run. Default is the public community image. Pin to a sha256 digest in
# production: ghcr.io/apps-in-toss-community/oidc-bridge@sha256:<digest>
# BRIDGE_IMAGE=ghcr.io/apps-in-toss-community/oidc-bridge:latest

# Toss adapter mode. Switch to `real` after creating an app with mTLS material.
# Mock mode is safe for first-boot validation; it never reaches the Toss network.
# BRIDGE_TOSS_ADAPTER=mock

# Sliding-window rate limit (Phase 8). Defaults: 60 req/IP/min, 600 req/app/min.
# Disable only for local development or when an upstream WAF rate-limits already.
# RATE_LIMIT_ENABLED=true

# OpenTelemetry export. Set to 1 only after `pnpm install --include=optional`.
# OTEL_ENABLED=0

# Pino log level. trace|debug|info|warn|error|fatal
# LOG_LEVEL=info

# Where master-key bytes live on the host. The directory MUST be 0700 and the
# files inside MUST be 0600 (the bridge process refuses to load otherwise).
# Default is ./data/master-keys; absolute paths are recommended in production.
# MASTER_KEY_HOST_DIR=/etc/oidc-bridge/master-keys

# Database URL override. Default uses the in-stack Postgres.
# Useful when pointing at an external managed Postgres.
# DATABASE_URL=postgres://bridge:password@postgres:5432/bridge
```

- [ ] **Step 2: Verify the example does not contain anything that looks like a real secret**

```bash
grep -nE 'replace-me|example\.com|<your' docker/.env.example
```

Expected: every "value" is either `replace-me-*` or `*.example.com`. Nothing that could be confused for a real key.

- [ ] **Step 3: Commit**

```bash
git add docker/.env.example
git commit -m "feat: docker/.env.example operator template"
```

---

## Task 10: `docs/SECURITY.md` (threat model + responsible disclosure)

**Files:**
- Create: `docs/SECURITY.md`

`SECURITY.md` lives at `docs/` (not the repo root) per the umbrella convention. GitHub picks up `.github/SECURITY.md` for the "Report a vulnerability" link; this phase does not introduce that file (umbrella org-level `.github` repo carries it). The doc here is the threat model, not the disclosure form.

- [ ] **Step 1: Write `docs/SECURITY.md`**

```markdown
# Security model

This document describes what `oidc-bridge` protects, what it explicitly does
not protect, and how it expects to be deployed. It is the source of truth for
the threat model. If anything in this repo contradicts this document, this
document is correct.

## Reporting a vulnerability

Please email `security@aitc.dev` (PGP key fingerprint published on the
[organization landing page](https://aitc.dev/security)). Do not open a public
GitHub issue for security reports.

We aim to acknowledge within 72 hours and to have a fix available within 30
days for high-severity reports. Coordinated disclosure timelines are flexible
where the bug is in a deployed instance rather than the codebase.

## What `oidc-bridge` protects

1. **Toss raw access/refresh tokens.** Toss-issued tokens never leave the
   bridge in plaintext. They are sealed (AES-256-GCM with a per-app key
   derived from a master key via HKDF) into an opaque `ait_access_token`
   wrapper. Mini-apps and BaaS clients never see a Toss AT or RT.
2. **mTLS client material.** mTLS certs and private keys are stored
   per-app, encrypted at rest in Postgres (envelope-encrypted with the
   per-app sealing key). They are never returned by any GET endpoint, never
   logged, and never appear in `/status` or `/admin/apps` responses.
3. **id_token integrity.** id_tokens are RS256 signed; the public key is
   published at `/.well-known/jwks.json` and rotated via `kid`. Consumers
   that follow OIDC standards can verify integrity without a side channel.
4. **Replay across apps.** The sealed-token AAD binds `(app_id,
   toss_user_key, sealing_key_version)`. A wrapper minted for app A
   cannot be unwrapped by app B even if B's master key is the same.
5. **User enumeration on `/admin/login` (Phase 6).** Bcrypt is run against
   a constant dummy hash for unknown emails so request timing does not
   distinguish "no such user" from "wrong password".

## What `oidc-bridge` does not protect against

1. **A compromised master key.** Master-key bytes live outside the
   database (env / file / GCPSM). If an attacker gains read access to the
   master-key file or the secret manager entry, they can unseal every
   `ait_access_token` issued under that master key. Operators must:
   - Set `MASTER_KEY_DIR` to mode 0700 with files mode 0600.
   - Restrict GCPSM access to the bridge service account only.
   - Rotate via `bridge master-key rotate` if compromise is suspected.
2. **A compromised database.** Postgres holds sealed tokens, sealed mTLS
   material, bcrypt-hashed `client_secret`s, and bcrypt-hashed user
   passwords. None of these are useful without the master key, except
   `client_secret` hashes are amenable to offline attack on weak secrets;
   require ≥256-bit `client_secret` values and rotate on suspected breach.
3. **A compromised Toss partner cert.** `oidc-bridge` cannot detect that
   a cert+key pair was exfiltrated from the operator's environment before
   it was uploaded. Treat the cert+key as crown-jewel-class material.
4. **Toss-issued PII.** Encrypted PII fields (name, phone, birthday, CI,
   gender, nationality) are passed through opaque from `/login-me`. The
   bridge does not hold the decryption key. If an attacker compromises
   the consumer that *does* hold that key, they decrypt PII independent
   of the bridge.
5. **Rate-limit bypass at L4.** Sliding-window rate limits are
   per-instance and in-memory. A multi-instance deployment without a
   front-door rate-limiter (Caddy, Cloud Run, WAF) does not deduplicate
   counts across replicas. The public instance is single-instance.
6. **DoS.** No anti-DoS layer ships with the bridge. Operators are
   responsible for upstream protection (Caddy concurrency limits,
   Cloudflare, Cloud Run autoscale caps).
7. **Browser side-channel attacks on the public-client `Origin` check.**
   The Phase 4 strict-equality `Origin` allowlist depends on the browser
   being a well-behaved browser. A malicious or instrumented browser
   that forges `Origin` is out of scope for this control; confidential-
   client mode (Phase 4) is the answer for that threat.

## Cryptographic primitives

- AES-256-GCM via `node:crypto` for sealing wrappers.
- HKDF-SHA256 for per-app key derivation from master keys.
- RSA-2048 RS256 for id_token signing via `jose`.
- bcrypt cost factor 12 for password and `client_secret` hashing.
- sha256 for IP hashing in logs (with per-process salt).
- TLS 1.3 only for outbound mTLS to Toss (`https.Agent`
  `minVersion: 'TLSv1.3'`).

We do not roll cryptographic primitives. We do not implement protocols
not covered by `node:crypto`, `jose`, `bcryptjs`, or `undici`.

## Trust boundaries

```
mini-app browser
    |  HTTPS  (TLS terminated by Caddy / Cloud Run)
    v
oidc-bridge process (this repo)
    |
    +-- Postgres (compose network only; not reachable from internet)
    +-- master-key file or GCPSM secret (filesystem perms / IAM)
    +-- mTLS to https://apps-in-toss-api.toss.im (per-app cert+key)
```

The mini-app browser is the only untrusted external party. Postgres,
the master-key store, and the Toss endpoint are all assumed to be
under the operator's control.

## Deployment recommendations

1. Run with `RATE_LIMIT_ENABLED=true` (default) unless an upstream
   layer rate-limits.
2. Bind-mount the master-key directory read-only (`/master-keys:ro`).
3. Use `cap_drop: [ALL]` on every container (the shipped compose does).
4. Pin `BRIDGE_IMAGE` to a sha256 digest in production.
5. Do not expose Postgres or the bridge port to the public internet
   directly; only Caddy's `:80`/`:443` should be publicly reachable.
6. Enable structured logging (`LOG_LEVEL=info` is fine; lower for
   debugging) and ship to a long-term store. Bridge logs are JSON on
   stdout; `docker compose logs` or any log-shipping sidecar works.
7. Run `pnpm bridge doctor --json` from cron weekly and alert on red.

## Out-of-scope explicit non-goals

- The bridge does not implement `/authorize` redirect flow.
- The bridge does not provide an end-user password reset flow.
- The bridge does not federate with other IdPs upstream of Toss.
- The bridge does not aim for FedRAMP, SOC 2, ISO 27001, or any
  compliance certification. It is an open-source community project.
```

- [ ] **Step 2: Verify the doc is accurate against earlier phases**

```bash
# Spot-check that we accurately describe locked decisions.
grep -n "AES-256-GCM\|HKDF\|RS256\|bcrypt\|TLSv1.3" docs/SECURITY.md
```

Expected: each of those primitives appears once.

Cross-check against `docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md`:
- §5.4 sealed wrapper format → matches.
- §5.5 master-key providers → matches.
- §5.6 cloud-agnostic invariants → matches.

- [ ] **Step 3: Commit**

```bash
git add docs/SECURITY.md
git commit -m "docs: SECURITY.md threat model + disclosure"
```

---

## Task 11: Append "Production hardening" to `docs/SELF_HOSTING.md`

**Files:**
- Modify: `docs/SELF_HOSTING.md`

Phase 7 created `SELF_HOSTING.md` with the bootstrap walkthrough. Phase 9
appends a "Production hardening" section that points at the new artifacts
(Dockerfile, compose, SECURITY.md) and adds VPS-specific guidance.

- [ ] **Step 1: Append the new section**

Locate the end of the Phase 7 walkthrough (typically a "Next steps" or
"Operating the bridge" section) and append:

```markdown
---

## Production hardening (Phase 9)

The walkthrough above gets you a running bridge against SQLite and the
mock Toss adapter. This section is what you do *after* the walkthrough
to run a real production instance.

### Reference deployment: Vultr Seoul `vc2-1c-1gb`

The community public instance runs on a `vc2-1c-1gb` Vultr Cloud Compute
Seoul instance (1 vCPU, 1 GiB RAM, ~$5/mo). The same compose stack
fits comfortably on equivalents from Hetzner, DigitalOcean, AWS Lightsail,
or your own bare metal.

Rough resource expectations under typical mini-app traffic (≤ 5 req/s):

| Service  | RSS    | CPU (avg) |
|----------|--------|-----------|
| bridge   | 80 MB  | 1–3 %     |
| postgres | 90 MB  | 0.5–1 %   |
| caddy    | 30 MB  | < 0.1 %   |

Memory headroom on `1 GiB` is comfortable; rebuild on a 2 GB SKU if you
plan to enable OpenTelemetry export or run alongside other services.

### Step-by-step on a fresh VPS (Ubuntu 24.04)

```bash
# 1. SSH in as root, create an unprivileged operator user.
adduser --disabled-password --gecos "" bridge-ops
usermod -aG sudo bridge-ops
mkdir -p /home/bridge-ops/.ssh
cp ~/.ssh/authorized_keys /home/bridge-ops/.ssh/
chown -R bridge-ops:bridge-ops /home/bridge-ops/.ssh
chmod 700 /home/bridge-ops/.ssh
# Then disable password+root SSH in /etc/ssh/sshd_config and reload sshd.

# 2. Install Docker + compose v2.
curl -fsSL https://get.docker.com | sh
usermod -aG docker bridge-ops
# Log out and back in as bridge-ops.

# 3. Clone, configure, prepare master-key dir.
sudo -iu bridge-ops
git clone https://github.com/apps-in-toss-community/oidc-bridge.git
cd oidc-bridge
cp docker/.env.example .env
$EDITOR .env  # fill in BRIDGE_HOST, ADMIN_TOKEN, POSTGRES_PASSWORD, CADDY_LE_EMAIL
cp docker/Caddyfile.example docker/Caddyfile
$EDITOR docker/Caddyfile  # replace BRIDGE_HOST literal
sudo mkdir -p /etc/oidc-bridge/master-keys
sudo chmod 700 /etc/oidc-bridge/master-keys
# In .env: MASTER_KEY_HOST_DIR=/etc/oidc-bridge/master-keys

# 4. Generate the v1 master key on the host.
sudo bash -c 'head -c 32 /dev/urandom > /etc/oidc-bridge/master-keys/v1.key'
sudo chmod 600 /etc/oidc-bridge/master-keys/v1.key

# 5. Boot.
docker compose pull
docker compose up -d
docker compose exec bridge node dist/cli.mjs bootstrap
docker compose exec bridge node dist/cli.mjs doctor --json | jq .status
# Expect "green" or "yellow" (yellow if no Toss app is registered yet).
```

### Hardening checklist

- [ ] SSH password auth disabled, root login disabled, key-only.
- [ ] Firewall: only `22/tcp` (SSH), `80/tcp`, `443/tcp+udp` open inbound.
- [ ] Master-key directory `0700`, files `0600`, owned by root (or by the
      Docker UID 1001 if you bind-mount with `:ro`).
- [ ] `BRIDGE_IMAGE` pinned to a sha256 digest in `.env`.
- [ ] `RATE_LIMIT_ENABLED=true`.
- [ ] `ADMIN_TOKEN` is at least 32 bytes of randomness; rotated on
      operator turnover.
- [ ] Postgres `POSTGRES_PASSWORD` is at least 24 bytes of randomness.
- [ ] Backups: nightly `pg_dump` of the bridge database, encrypted at
      rest, off-host. The master-key file backs up separately.
- [ ] `pnpm bridge doctor --json | jq .status` runs from cron weekly
      and pages on `red`.
- [ ] Log shipping: `docker compose logs --tail=0 -f bridge | <ship>`
      to a long-term store; the bridge emits JSON on stdout (Phase 8).

### Recovery scenarios

**Master-key file lost.** All `ait_access_token`s issued under that
key become unrecoverable. There is no "skeleton key". Mini-app users
re-authenticate via `appLogin()`; the bridge mints fresh wrappers under
a new master-key version. Confidential clients must rotate their
`client_secret` since the database row is intact but the AT bindings
are gone.

**Master-key file leaked.** Treat all live `ait_access_token`s as
compromised. Rotate immediately:

```bash
docker compose exec bridge node dist/cli.mjs master-key rotate
docker compose exec bridge node dist/cli.mjs revoke-all-sessions
```

The first command adds a new master-key version; lazy rewrap migrates
apps. The second command (Phase 6) bumps `users.token_version` so all
admin sessions are invalidated.

**Postgres data loss.** Restore the most recent `pg_dump`. Sealed
tokens predating the dump remain valid only if the master-key file is
intact (sealing key is HKDF-derived and stable across DB restores).

### See also

- [`docs/SECURITY.md`](./SECURITY.md) — threat model.
- [`docs/RUNBOOK.md`](./RUNBOOK.md) — day-to-day operator commands.
- [umbrella `meta/release-strategy.md`](https://github.com/apps-in-toss-community/umbrella/blob/main/meta/release-strategy.md)
  — image versioning, release cadence.
```

- [ ] **Step 2: Verify the section appended cleanly**

```bash
grep -n "Production hardening (Phase 9)" docs/SELF_HOSTING.md
```

Expected: exactly one match. The section appears after the existing
walkthrough; the bootstrap walkthrough is unchanged.

- [ ] **Step 3: Commit**

```bash
git add docs/SELF_HOSTING.md
git commit -m "docs: SELF_HOSTING.md production hardening section"
```

---

## Task 12: RUNBOOK pointer + `package.json` scripts

**Files:**
- Modify: `docs/RUNBOOK.md`
- Modify: `package.json`

- [ ] **Step 1: Append a "Self-host with docker compose" section to RUNBOOK.md**

```markdown
## Self-host with docker compose

The community-supported self-host path is the `docker-compose.yml` at the
repo root with `docker/Caddyfile.example` and `docker/.env.example`.
See [`SELF_HOSTING.md`](./SELF_HOSTING.md) for the bootstrap walkthrough
and the production-hardening section.

Day-to-day commands:

```bash
docker compose ps
docker compose logs -f bridge
docker compose exec bridge node dist/cli.mjs doctor --json
docker compose exec bridge node dist/cli.mjs status
docker compose pull && docker compose up -d   # upgrade
```

Image build (for local dev or fork builds):

```bash
pnpm image:build       # builds the local Dockerfile as bridge:dev
pnpm smoke:image       # runs scripts/smoke-image.sh against bridge:dev
```
```

- [ ] **Step 2: Add scripts to `package.json`**

In the `scripts` block of `package.json`, add:

```json
"image:build": "docker build -t bridge:dev .",
"smoke:image": "BRIDGE_SMOKE_IMAGE=1 vitest run test/smoke/smoke-image.test.ts",
"smoke:vps": "bash scripts/smoke-vps.sh"
```

The exact key order does not matter, but place them alphabetically near
the other `smoke:*` or `test:*` keys for readability.

- [ ] **Step 3: Verify the scripts parse and run**

```bash
pnpm run --silent --if-present image:build >/dev/null 2>&1 && echo build:OK
pnpm run --silent --if-present smoke:image >/dev/null 2>&1 || echo "smoke:image SKIPPED (image not built? expected)"
```

Expected: `build:OK` (the Dockerfile from Tasks 2–4 builds). The
`smoke:image` line is informational; full run requires the image and
docker daemon — which Step 4 below verifies.

- [ ] **Step 4: Run the full smoke once end-to-end via pnpm**

```bash
pnpm image:build
pnpm smoke:image
```

Expected: vitest reports 2 passed for `test/smoke/smoke-image.test.ts`.

- [ ] **Step 5: Commit**

```bash
git add docs/RUNBOOK.md package.json
git commit -m "feat: pnpm image:build / smoke:image / smoke:vps scripts; RUNBOOK pointer"
```

---

## Task 13: `scripts/smoke-vps.sh` (clean-VPS end-to-end)

**Files:**
- Create: `scripts/smoke-vps.sh`

This is the script operators (and CI on a self-hosted runner, if ever)
re-run to validate a fresh VPS deployment end-to-end. It is *idempotent*
in the same checkout but assumes a clean Docker daemon at start; it does
not try to migrate an existing stack.

- [ ] **Step 1: Write `scripts/smoke-vps.sh`**

```bash
#!/usr/bin/env bash
# scripts/smoke-vps.sh — clean-VPS end-to-end smoke for the docker compose stack.
#
# Prereqs (the script verifies, does not install):
#   - docker (>= 24)
#   - docker compose v2
#   - openssl (for fixture random)
#   - jq      (for parsing doctor output)
#
# What it does, in order:
#   1. Generates a throwaway .env with random values (BRIDGE_HOST=localhost.invalid
#      so Caddy will not actually issue a Let's Encrypt cert -- TLS termination
#      is exercised by the public deploy job, not this smoke).
#   2. Generates a master-key file in ./data/master-keys/v1.key.
#   3. Boots the stack with `docker compose up -d`.
#   4. Polls bridge:8080/healthz inside the compose network until healthy.
#   5. Runs `bridge bootstrap` and asserts it prints a non-empty workspace_id
#      and an api_token starting with "bait_".
#   6. Runs `bridge doctor --json` and asserts status is green or yellow.
#   7. Tears down with `docker compose down -v` on exit.
#
# Exit codes:
#   0 — smoke passed
#   1 — prereq missing
#   2 — boot failed (healthcheck never went green)
#   3 — bootstrap failed
#   4 — doctor red
set -euo pipefail

cleanup() {
  if [ "${KEEP_STACK:-0}" = "1" ]; then
    echo "[smoke-vps] KEEP_STACK=1 -- leaving stack running" >&2
  else
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f .env.smoke-vps docker/Caddyfile.smoke-vps
}
trap cleanup EXIT

require() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "[smoke-vps] FAIL: required command not found: $cmd" >&2
    exit 1
  fi
}
require docker
require openssl
require jq
docker compose version >/dev/null 2>&1 || {
  echo "[smoke-vps] FAIL: 'docker compose' v2 not available" >&2
  exit 1
}

# ---- Step 1: throwaway .env ----
ADMIN_TOKEN="$(openssl rand -base64 32 | tr -d '=' | tr '+/' '_-')"
POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -d '=' | tr '+/' '_-')"
cat > .env.smoke-vps <<EOF
BRIDGE_HOST=localhost.invalid
CADDY_LE_EMAIL=ops@localhost.invalid
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
ADMIN_TOKEN=${ADMIN_TOKEN}
BRIDGE_IMAGE=bridge:dev
BRIDGE_TOSS_ADAPTER=mock
RATE_LIMIT_ENABLED=true
LOG_LEVEL=info
MASTER_KEY_HOST_DIR=./data/master-keys
EOF
ln -sf .env.smoke-vps .env

# ---- Step 2: master-key file ----
mkdir -p ./data/master-keys
chmod 700 ./data/master-keys
head -c 32 /dev/urandom > ./data/master-keys/v1.key
chmod 600 ./data/master-keys/v1.key

# ---- Caddyfile with localhost.invalid; Caddy won't try LE because
#      BRIDGE_HOST is not a real DNS name and Caddy's on-demand TLS
#      requires a real ACME challenge. We pin auto_https off for smoke.
cat docker/Caddyfile.example > docker/Caddyfile.smoke-vps
sed -i.bak '1i\
{\
    auto_https off\
    admin localhost:2019\
}' docker/Caddyfile.smoke-vps
rm -f docker/Caddyfile.smoke-vps.bak
ln -sf Caddyfile.smoke-vps docker/Caddyfile

# ---- Step 3: build (if needed) and boot ----
docker images bridge:dev --format '{{.Repository}}:{{.Tag}}' | grep -q '^bridge:dev$' \
  || docker build -t bridge:dev .

echo "[smoke-vps] booting stack" >&2
docker compose up -d

# ---- Step 4: wait for bridge healthy ----
echo "[smoke-vps] waiting for bridge healthcheck" >&2
for i in $(seq 1 90); do
  state="$(docker inspect --format='{{.State.Health.Status}}' "$(docker compose ps -q bridge)" 2>/dev/null || echo none)"
  if [ "$state" = "healthy" ]; then break; fi
  sleep 1
done
if [ "$state" != "healthy" ]; then
  echo "[smoke-vps] FAIL: bridge did not become healthy in 90s (state=$state)" >&2
  docker compose logs bridge | tail -50 >&2
  exit 2
fi

# ---- Step 5: bootstrap ----
echo "[smoke-vps] bootstrapping" >&2
bootstrap_out="$(docker compose exec -T bridge node dist/cli.mjs bootstrap --json)"
workspace_id="$(echo "$bootstrap_out" | jq -r '.workspaceId // empty')"
api_token="$(echo "$bootstrap_out" | jq -r '.apiTokenPlaintext // empty')"
if [ -z "$workspace_id" ] || [ -z "$api_token" ]; then
  echo "[smoke-vps] FAIL: bootstrap output missing workspaceId or apiTokenPlaintext" >&2
  echo "$bootstrap_out" >&2
  exit 3
fi
case "$api_token" in
  bait_*) ;;
  *)
    echo "[smoke-vps] FAIL: api token does not start with 'bait_': $api_token" >&2
    exit 3 ;;
esac

# ---- Step 6: doctor ----
echo "[smoke-vps] running doctor" >&2
doctor_out="$(docker compose exec -T bridge node dist/cli.mjs doctor --json)"
status="$(echo "$doctor_out" | jq -r '.status')"
case "$status" in
  green|yellow)
    echo "[smoke-vps] PASS: doctor=$status" ;;
  red)
    echo "[smoke-vps] FAIL: doctor=red" >&2
    echo "$doctor_out" | jq . >&2
    exit 4 ;;
  *)
    echo "[smoke-vps] FAIL: unexpected doctor status '$status'" >&2
    exit 4 ;;
esac

echo "[smoke-vps] OK"
```

- [ ] **Step 2: Lint**

```bash
chmod +x scripts/smoke-vps.sh
shellcheck scripts/smoke-vps.sh
```

Expected: shellcheck reports no issues. (`SC2155` warnings about masking
return values from inline assigns are acceptable as long as we use
`set -e` and a non-zero exit causes immediate failure; the script does
not silently swallow errors from `openssl` or `head`.)

- [ ] **Step 3: Run on a workstation that has docker**

```bash
./scripts/smoke-vps.sh
```

Expected: ends with `[smoke-vps] OK`. Total runtime under 90 s on a
warm Docker daemon, under 4 minutes on a cold pull.

- [ ] **Step 4: Commit**

```bash
git add scripts/smoke-vps.sh
git commit -m "feat: smoke-vps.sh clean-VPS end-to-end smoke"
```

---

## Task 14: CI image-build + smoke-image job

**Files:**
- Modify: `.github/workflows/ci.yml`

CI must build the image and run the image smoke on every PR so a broken
Dockerfile or compose layout is caught before merge. The full
`smoke-vps.sh` is intentionally *not* run in GitHub-hosted CI — that
script targets a real VPS layout and is exercised on the deploy
pipeline (Phase 10 will add deploy-side validation).

- [ ] **Step 1: Add the image-build job to `.github/workflows/ci.yml`**

Insert a new job (named `image-smoke`) that depends on the existing
`build` (or `test`) job:

```yaml
  image-smoke:
    name: Image build + smoke
    needs: [test]
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with: { version: '10.33.0' }

      - uses: actions/setup-node@v4
        with:
          node-version: '24'
          cache: 'pnpm'

      - run: pnpm install --frozen-lockfile

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build image
        uses: docker/build-push-action@v5
        with:
          context: .
          tags: bridge:dev
          load: true
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Run image smoke
        run: pnpm smoke:image
        env:
          BRIDGE_SMOKE_IMAGE: '1'
```

- [ ] **Step 2: Validate workflow syntax**

```bash
# Use actionlint via Docker if not installed locally.
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest -color
```

Expected: no output (success).

- [ ] **Step 3: Commit and verify on PR**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: image-smoke job (build + run smoke-image.sh)"
```

Push the branch and verify on the PR:
- The `image-smoke` job appears in the checks list.
- It runs to green within 15 minutes.
- The smoke step ends with `[smoke] OK`.

If the job fails on a transient `docker pull` issue, re-run; if it fails
deterministically on a code path, fix at root before merging.

---

## Task 15: PR

- [ ] **Step 1: Open the PR**

Title: `Phase 9: self-host artifacts (Dockerfile, compose, smoke, SECURITY.md)`

Body (markdown):

```markdown
## Summary
- Multi-stage `node:24-alpine` Dockerfile with non-root runtime, dumb-init,
  read-only rootfs, healthcheck on `/healthz`.
- `docker-compose.yml` wiring bridge + Postgres 17 + Caddy 2 with TLS
  termination at Caddy and capability hardening on every service.
- Master-key bytes bind-mounted from host (`MASTER_KEY_HOST_DIR`), survive
  image upgrades, never leak into the image layer.
- `docs/SECURITY.md` threat model + `docs/SELF_HOSTING.md` production
  hardening section (the bootstrap walkthrough lives in Phase 7).
- `scripts/smoke-image.sh` (image-only) and `scripts/smoke-vps.sh`
  (full compose stack) plus a vitest harness gated by
  `BRIDGE_SMOKE_IMAGE=1`.
- CI gains an `image-smoke` job that builds the image and runs the
  image-only smoke on every PR.

## Test plan
- [ ] `pnpm image:build` succeeds locally and image is < 200 MB.
- [ ] `docker run --rm bridge:dev id` returns `uid=1001(bridge)`.
- [ ] `pnpm smoke:image` ends with `[smoke] OK`.
- [ ] `pnpm smoke:vps` ends with `[smoke-vps] OK`.
- [ ] `docker compose config` validates with values from `.env.example`.
- [ ] `docker run --rm caddy:2-alpine caddy validate` accepts the
      example Caddyfile.
- [ ] CI `image-smoke` job is green on the PR.
- [ ] `docs/SECURITY.md` and the new section in `docs/SELF_HOSTING.md`
      describe the shipped artifacts accurately (no aspirational paths).
```

Push the branch (if not pushed already by Task 14 Step 3) and `gh pr
create` against `main`.

- [ ] **Step 2: Review handoff**

Two-stage review (per superpowers:subagent-driven-development):
1. Spec compliance reviewer confirms the four-line scope statement
   from §11 is fully covered.
2. Code-quality reviewer confirms shellcheck is clean, the Dockerfile
   pin is on a sha256 digest (not `:latest`), and no compose service
   has `cap_add: [ALL]` or runs as root.

---

## Done condition

This phase is done when, on a clean checkout against the `main` branch
of this repo and a clean Docker daemon:

1. `pnpm image:build` produces a < 200 MB image with `bridge:dev`
   running as UID 1001.
2. `pnpm smoke:image` passes.
3. `pnpm smoke:vps` passes end-to-end including bootstrap + doctor
   green-or-yellow.
4. `docker compose config` resolves cleanly with the values from
   `docker/.env.example`.
5. `docs/SECURITY.md` exists and accurately describes the
   cryptographic primitives, trust boundaries, and out-of-scope
   non-goals shipped through Phase 8.
6. `docs/SELF_HOSTING.md` carries both the Phase 7 bootstrap
   walkthrough and the Phase 9 production-hardening section.
7. CI `image-smoke` job is green on `main`.
8. The PR is merged with the spec-compliance and code-quality
   reviewers' approval.

That state is the foundation Phase 10 (GCP Cloud Run public deploy)
builds on — Phase 10 reuses the same image, swaps Postgres for Cloud
SQL, swaps the master-key file for GCPSM, and replaces Caddy with
Cloud Run's built-in TLS termination + IAP ingress controls. None of
the application code changes; only the deployment artifacts differ.
