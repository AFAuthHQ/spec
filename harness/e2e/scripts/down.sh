#!/usr/bin/env bash
# Tear down the e2e stack and remove volumes (so the next `up.sh` is
# a clean slate). Use `docker compose stop` directly if you want to
# preserve state between runs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE/.."

docker compose down -v --remove-orphans
