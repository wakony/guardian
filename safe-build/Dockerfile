# =============================================================================
# SAFE-BUILD — Network-Isolated Build Container
# =============================================================================
# Two-stage build that prevents supply chain malware from calling home:
#
# Stage 1 (deps): Install dependencies WITH network access
# Stage 2 (build): Build the project WITHOUT network access
#
# If malicious code in a config file tries to contact a C2 server during
# the build phase, the request will fail — no DNS, no TCP, no exfiltration.
# =============================================================================

# ─── Stage 1: Dependency Installation (network allowed) ─────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

# Copy only package manifests for dependency resolution
COPY package.json ./
COPY package-lock.json* pnpm-lock.yaml* yarn.lock* ./

# Install dependencies (network is available here)
RUN if [ -f pnpm-lock.yaml ]; then \
      corepack enable pnpm && pnpm install --frozen-lockfile; \
    elif [ -f yarn.lock ]; then \
      yarn install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then \
      npm ci; \
    else \
      npm install; \
    fi

# ─── Stage 2: Build (NO network access) ─────────────────────────────────────
# IMPORTANT: When running this stage, use --network=none
#   docker build --target build --network=none ...
#
# This ensures that even if malicious code is present in config files,
# it cannot:
#   - Resolve C2 addresses via blockchain APIs
#   - Exfiltrate credentials to attacker servers
#   - Download additional payloads
# =============================================================================
FROM node:20-alpine AS build

WORKDIR /app

# Copy node_modules from deps stage (already verified clean install)
COPY --from=deps /app/node_modules ./node_modules

# Copy source code
COPY . .

# SECURITY: Only expose variables needed for build
# DO NOT pass: GITHUB_TOKEN, DATABASE_URL, SUPABASE_KEY, STRIPE_KEY, etc.
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Run the build
# This executes WITHOUT network — any C2 callback will fail
RUN npm run build

# ─── Stage 3: Production output (optional) ──────────────────────────────────
FROM node:20-alpine AS production

WORKDIR /app

COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules

ENV NODE_ENV=production
EXPOSE 3000

CMD ["npm", "start"]
