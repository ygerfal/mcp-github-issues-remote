# Multi-stage build for mcp-github-issues-remote
#
# Stage 1: install + compile TypeScript
# Stage 2: minimal runtime with production deps + compiled JS

FROM node:20-bookworm-slim AS build

# better-sqlite3 needs a C toolchain to compile its native bindings
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Prune to production deps only for the runtime layer
RUN npm prune --omit=dev


FROM node:20-bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/package.json ./package.json

# Fly.io mounts /data volume; SQLITE_PATH points there in fly.toml.
RUN mkdir -p /data

ENV NODE_ENV=production
EXPOSE 8787

# tini reaps zombie children and forwards signals cleanly
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "dist/server.js"]
