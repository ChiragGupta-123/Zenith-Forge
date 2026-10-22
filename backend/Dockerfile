# ----------------------------------------------------
# Stage 1: Build & Compile TypeScript
# ----------------------------------------------------
FROM node:22-bookworm-slim AS builder

WORKDIR /app

# Install native compilation dependencies for better-sqlite3
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json tsconfig.json ./
RUN npm ci

COPY src ./src
RUN npm run build

# Remove development dependencies to keep final image minimal
RUN npm prune --production

# ----------------------------------------------------
# Stage 2: Hardened Production Runtime
# ----------------------------------------------------
FROM node:22-bookworm-slim AS runner

WORKDIR /app

# Install curl for container health check
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production
ENV PORT=4000
ENV DEVCOLLAB_DB_PATH=/data/sqlite/devcollab.sqlite

# Prepare persistent SQLite directory owned by non-root user
RUN mkdir -p /data/sqlite && chown -R node:node /data/sqlite

COPY package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Run as unprivileged node user
USER node

EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:4000/api/health || exit 1

CMD ["node", "dist/server.js"]
