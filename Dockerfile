# syntax=docker/dockerfile:1.7

# ---------- builder ----------
# Install full deps once, build with tsdown, then prune to a prod-only tree.
FROM node:24-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.json ./
COPY src ./src
RUN pnpm build

# Prune to production deps for the runtime stage.
RUN pnpm prune --prod


# ---------- runtime ----------
FROM node:24-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    PORT=8080

USER node

COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist
COPY --chown=node:node --from=builder /app/package.json ./package.json

EXPOSE 8080

# Uses Node's global fetch (Node 24) instead of relying on busybox wget.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Node as PID 1 is fine for this stateless service — Cloud Run delivers
# SIGTERM directly to PID 1 and @hono/node-server handles it. No `tini`
# needed. `--enable-source-maps` keeps stack traces readable in logs.
CMD ["node", "--enable-source-maps", "dist/server.mjs"]
