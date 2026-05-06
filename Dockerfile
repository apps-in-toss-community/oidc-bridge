# syntax=docker/dockerfile:1.7

# ----- Stage 1: deps -----
# Install full deps, compile dist/, and prune to production deps. The runtime
# stage cherry-picks /app/node_modules + /app/dist + /app/drizzle from this
# stage. We collapse install + build + prune into one stage rather than three
# because pnpm deploy doesn't work for non-workspace single-package repos
# (ERR_PNPM_CANNOT_DEPLOY) so the lossless prune step is just `pnpm prune`.
#
# Alpine builder toolchain is required because better-sqlite3 ships no musl
# prebuild and falls back to a node-gyp rebuild during install. The runtime
# stage stays lean — it never sees python3/make/g++.
FROM node:24-alpine@sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f AS deps

RUN apk add --no-cache python3 make g++

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
COPY cli ./cli
COPY drizzle ./drizzle

# Compile here (rather than in a separate build stage) so we keep the same
# pnpm store cache hot across both compile and prune. Output is
# dist/server.mjs (server entry) and dist/index.mjs (CLI entry); pnpm build
# invokes both build:server and build:cli.
RUN pnpm build \
    && test -f dist/server.mjs && test -f dist/index.mjs

# Prune to production deps. We keep the pruned tree in-place (./node_modules)
# and the runtime stage cherry-picks it. pnpm deploy is not used because
# it requires a workspace and this repo is a single package.
RUN pnpm prune --prod

# ----- Stage 2: runtime -----
# Minimal alpine layer with the pruned node_modules + dist/ + drizzle migrations.
# Runs unprivileged as bridge:1001 with dumb-init as PID 1.
FROM node:24-alpine@sha256:d1b3b4da11eefd5941e7f0b9cf17783fc99d9c6fc34884a665f40a06dbdfc94f AS runtime

# dumb-init reaps zombies and forwards SIGTERM to the node process so
# `docker stop` triggers @hono/node-server's graceful shutdown.
# busybox wget (already in alpine) handles the HEALTHCHECK probe.
RUN apk add --no-cache dumb-init

# Non-root runtime user. Pinning UID/GID to 1001 lets operators chown
# bind-mounted host directories to the same UID without coordinating with
# the image internals.
RUN addgroup -g 1001 -S bridge \
    && adduser -u 1001 -S -G bridge -h /home/bridge -s /sbin/nologin bridge

WORKDIR /app

# Pre-create the SQLite default data directory and chown to bridge so the
# runtime can create files under /app/data when STORAGE=sqlite.
RUN mkdir -p /app/data && chown -R bridge:bridge /app/data

# Pruned prod-only node_modules from the deps stage.
COPY --from=deps --chown=bridge:bridge /app/node_modules ./node_modules
# Build output and package.json (the latter so dist/index.mjs --version works
# and so node resolves "type": "module" for the .mjs entries).
COPY --from=deps --chown=bridge:bridge /app/dist ./dist
COPY --from=deps --chown=bridge:bridge /app/package.json ./package.json
# Drizzle migration SQL files (consumed by drizzle-kit migrate at first boot
# in self-host setups; the running server itself does not depend on them
# being present, but keeping them in-image keeps the operator workflow simple).
COPY --from=deps --chown=bridge:bridge /app/drizzle ./drizzle

USER bridge

# Bridge speaks plain HTTP. Caddy / Cloud Run / a reverse-proxy terminates TLS.
EXPOSE 8080

ENV NODE_ENV=production \
    NODE_OPTIONS="--enable-source-maps" \
    PORT=8080

# /healthz is exempt from the Phase 8 rate limit so probing here doesn't
# consume per-IP budget. Container is unhealthy after 3 consecutive failures.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
  CMD wget --quiet --spider http://127.0.0.1:8080/healthz || exit 1

# dumb-init forwards signals; node binary runs the compiled server entry.
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "dist/server.mjs"]
