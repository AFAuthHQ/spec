#!/usr/bin/env bash
# Bring up the e2e dependency-side stack and poll the host-side health
# endpoints until each service is reachable.
#
# Postgres/Redis use Docker healthchecks (their Alpine images ship
# pg_isready / redis-cli). The Node services (trust, registry,
# reference-server) don't ship wget or curl, so we poll their
# /healthz from the host instead.
#
# Usage:
#   ./scripts/up.sh
#
# Environment:
#   E2E_TRUST_DIR      path to AFAuthHQ/trust source     (default: ../../../trust)
#   E2E_REGISTRY_DIR   path to AFAuthHQ/registry source  (default: ../../../registry)
#   E2E_WAIT_SECONDS   per-service wait cap              (default: 120)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.."

WAIT="${E2E_WAIT_SECONDS:-120}"

echo "[e2e] compose build..."
docker compose build

echo "[e2e] compose up -d..."
docker compose up -d

wait_for() {
  local name="$1"
  local url="$2"
  printf "  %s ..." "$name"
  local end=$(( $(date +%s) + WAIT ))
  while :; do
    if curl -fsS -o /dev/null --max-time 2 "$url" 2>/dev/null; then
      echo " ok"
      return 0
    fi
    if [ "$(date +%s)" -ge "$end" ]; then
      echo " TIMEOUT"
      echo "[e2e] $name did not become healthy in ${WAIT}s. logs:"
      docker compose logs --tail=80 "$name" || true
      return 1
    fi
    sleep 2
  done
}

echo "[e2e] waiting for services (cap ${WAIT}s each)..."
wait_for trust                     http://localhost:4001/healthz
wait_for registry                  http://localhost:4002/healthz
wait_for reference-server          http://localhost:4003/healthz
wait_for reference-server-b        http://localhost:4004/healthz
wait_for reference-server-attested http://localhost:4005/healthz

echo "[e2e] stack is up:"
echo "  trust                     → http://localhost:4001"
echo "  registry                  → http://localhost:4002"
echo "  reference-server          → http://localhost:4003"
echo "  reference-server-b        → http://localhost:4004"
echo "  reference-server-attested → http://localhost:4005"
