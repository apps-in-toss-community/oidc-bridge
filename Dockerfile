# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM node:24-alpine AS builder

WORKDIR /app

# Pin pnpm to the org-standard version via corepack.
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate

# Install deps against the lockfile only (better cache hits).
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Build.
COPY tsconfig.json biome.json ./
COPY src ./src
RUN pnpm build

# Produce a production-only node_modules in a second step so the runtime
# stage doesn't ship devDependencies.
RUN pnpm install --frozen-lockfile --prod


# ---------- runtime ----------
FROM node:24-alpine AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    PORT=8080

# Non-root user (node:24-alpine already ships `node` uid 1000).
USER node

COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist
COPY --chown=node:node --from=builder /app/package.json ./package.json

EXPOSE 8080

CMD ["node", "dist/server.mjs"]
