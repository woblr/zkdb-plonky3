# ─────────────────────────────────────────────────────────────────────────────
# Stage 1: Build Next.js frontend (standalone output)
# ─────────────────────────────────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
# Backend will be on port 3001 inside the container (same as prod env)
ENV NEXT_PUBLIC_API_URL=http://127.0.0.1:3001
RUN npm run build

# ─────────────────────────────────────────────────────────────────────────────
# Stage 2: Build Rust backend (release mode — mandatory for ZK performance)
# ─────────────────────────────────────────────────────────────────────────────
FROM rustlang/rust:nightly-slim AS rust-builder
WORKDIR /app

# Install system deps for linking
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy everything and build (git deps can't use layer cache anyway)
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

# ─────────────────────────────────────────────────────────────────────────────
# Stage 3: Runtime image
# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime
WORKDIR /app

# Minimal runtime deps
RUN apt-get update && apt-get install -y ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 for running Next.js standalone
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*

# Copy Rust binary
COPY --from=rust-builder /app/target/release/zkdb /usr/local/bin/zkdb

# Copy Next.js standalone output
COPY --from=frontend-builder /app/frontend/.next/standalone ./frontend/
COPY --from=frontend-builder /app/frontend/.next/static ./frontend/.next/static
COPY --from=frontend-builder /app/frontend/public ./frontend/public

# Startup script: runs both services concurrently
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Single exposed port (Coolify will forward to this)
EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000
ENV ZKDB_BACKEND=plonky3

ENTRYPOINT ["/docker-entrypoint.sh"]
