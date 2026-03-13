#!/usr/bin/env bash
# =============================================================================
# safe-build.sh — Network-Isolated Build Wrapper
# =============================================================================
# Runs a two-phase build: dependencies with network, build without network.
# If malicious code in a config file tries to contact a C2 server, it fails.
#
# Usage:
#   ./safe-build.sh [project-dir] [build-command]
#   ./safe-build.sh /path/to/project "next build"
#   ./safe-build.sh .                "npm run build"
#
# Modes:
#   Default: Uses Docker containers with network isolation
#   --local: Uses a direct approach without Docker (requires Linux + iptables)
# =============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PROJECT_DIR="${1:-.}"
BUILD_CMD="${2:-npm run build}"
MODE="docker"

if [[ "${3:-}" == "--local" ]]; then
  MODE="local"
fi

PROJECT_DIR=$(cd "$PROJECT_DIR" && pwd)

echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  SAFE-BUILD — Network-Isolated Build System          ${CYAN}║${NC}"
echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${CYAN}║${NC}  Project: $(echo "$PROJECT_DIR" | tail -c 44 | head -c 44)  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Command: $(echo "$BUILD_CMD" | tail -c 44 | head -c 44)  ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Mode:    $MODE                                       ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Validate project
if [ ! -f "$PROJECT_DIR/package.json" ]; then
  echo -e "${RED}Error: No package.json found in $PROJECT_DIR${NC}"
  exit 1
fi

if [ "$MODE" = "docker" ]; then
  # ── Docker Mode ──
  if ! command -v docker &>/dev/null; then
    echo -e "${RED}Error: Docker not found. Install Docker or use --local mode.${NC}"
    exit 1
  fi

  CONTAINER_NAME="safe-build-$(date +%s)"

  echo -e "${CYAN}Phase 1: Installing dependencies (network ON)...${NC}"
  docker run --rm \
    --name "${CONTAINER_NAME}-deps" \
    -v "$PROJECT_DIR:/app" \
    -w /app \
    node:20-alpine \
    sh -c "if [ -f pnpm-lock.yaml ]; then corepack enable pnpm && pnpm install --frozen-lockfile; elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; elif [ -f package-lock.json ]; then npm ci; else npm install; fi"

  DEPS_EXIT=$?
  if [ "$DEPS_EXIT" -ne 0 ]; then
    echo -e "${RED}Dependency installation failed (exit $DEPS_EXIT).${NC}"
    exit $DEPS_EXIT
  fi
  echo -e "${GREEN}Dependencies installed successfully.${NC}"

  echo ""
  echo -e "${CYAN}Phase 2: Building (network OFF)...${NC}"
  echo -e "${YELLOW}Any network requests during build will FAIL — this is intentional.${NC}"

  docker run --rm \
    --name "${CONTAINER_NAME}-build" \
    --network none \
    -v "$PROJECT_DIR:/app:ro" \
    -v "$PROJECT_DIR/node_modules:/app/node_modules:ro" \
    -v "$PROJECT_DIR/.next:/app/.next" \
    -v "$PROJECT_DIR/dist:/app/dist" \
    -w /app \
    -e NODE_ENV=production \
    -e NEXT_TELEMETRY_DISABLED=1 \
    node:20-alpine \
    sh -c "$BUILD_CMD"

  BUILD_EXIT=$?

  if [ "$BUILD_EXIT" -ne 0 ]; then
    echo ""
    echo -e "${RED}Build failed (exit $BUILD_EXIT).${NC}"
    echo -e "${YELLOW}If the build failed due to network errors, this may indicate${NC}"
    echo -e "${YELLOW}that build config files are trying to contact external servers.${NC}"
    echo -e "${YELLOW}This is a strong indicator of supply chain compromise.${NC}"
    exit $BUILD_EXIT
  fi

  echo ""
  echo -e "${GREEN}Build completed successfully in network-isolated container.${NC}"
  echo -e "${GREEN}No external connections were possible during the build.${NC}"

elif [ "$MODE" = "local" ]; then
  # ── Local Mode (Linux + iptables) ──
  echo -e "${YELLOW}Local mode requires root privileges for network blocking.${NC}"

  echo -e "${CYAN}Phase 1: Installing dependencies (network ON)...${NC}"
  cd "$PROJECT_DIR"
  if [ -f pnpm-lock.yaml ]; then
    pnpm install --frozen-lockfile
  elif [ -f yarn.lock ]; then
    yarn install --frozen-lockfile
  elif [ -f package-lock.json ]; then
    npm ci
  else
    npm install
  fi

  echo -e "${CYAN}Phase 2: Building (network blocked via iptables)...${NC}"

  # Create a network namespace for the build
  BUILD_USER="safe-build-$$"

  echo -e "${YELLOW}Blocking network for build process...${NC}"

  # Use unshare to create a network namespace with no connectivity
  if command -v unshare &>/dev/null; then
    unshare --net -- sh -c "
      export NODE_ENV=production
      export NEXT_TELEMETRY_DISABLED=1
      cd '$PROJECT_DIR'
      $BUILD_CMD
    "
    BUILD_EXIT=$?
  else
    echo -e "${RED}unshare not available. Cannot isolate network in local mode.${NC}"
    echo -e "${YELLOW}Falling back to Docker mode.${NC}"
    exec "$0" "$PROJECT_DIR" "$BUILD_CMD"
  fi

  if [ "$BUILD_EXIT" -ne 0 ]; then
    echo -e "${RED}Build failed (exit $BUILD_EXIT) — possible C2 callback attempt blocked.${NC}"
    exit $BUILD_EXIT
  fi

  echo -e "${GREEN}Build completed in network-isolated environment.${NC}"
fi
