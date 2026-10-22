# ----------------------------------------------------
# Stage 1: Build Vite Production Assets
# ----------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json tsconfig.json vite.config.ts tailwind.config.js postcss.config.js index.html ./
RUN npm ci

COPY src ./src

# Build-time environment arguments (defaults to relative paths for same-origin proxy)
ARG VITE_API_URL=/api
ARG VITE_SOCKET_URL=/
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_SOCKET_URL=$VITE_SOCKET_URL

RUN npm run build

# ----------------------------------------------------
# Stage 2: Serve via Hardened Nginx Alpine
# ----------------------------------------------------
FROM nginx:alpine AS runner

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
