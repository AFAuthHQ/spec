#!/usr/bin/env bash
# Build the workspace @afauthhq/{core,server} packages and drop versioned
# tarballs into reference-server/vendor/ so the e2e reference-server installs
# the CURRENT SDK source (versions.json: typescript_sdk_sha=main) instead of
# whatever is published to npm. Run by ./scripts/up.sh and by the CI e2e job
# BEFORE `docker compose build`.
#
# Environment:
#   E2E_SDK_DIR   path to AFAuthHQ/typescript-sdk source (default: ../../../typescript-sdk)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(cd "$HERE/.." && pwd)"
SDK_DIR="${E2E_SDK_DIR:-$(cd "$E2E_DIR/../../../typescript-sdk" && pwd)}"
VENDOR="$E2E_DIR/reference-server/vendor"

echo "[pack-sdk] SDK source: $SDK_DIR"
[ -d "$SDK_DIR/packages/server" ] || { echo "[pack-sdk] not a typescript-sdk checkout: $SDK_DIR" >&2; exit 1; }

echo "[pack-sdk] install + build (core, server)..."
( cd "$SDK_DIR" && pnpm install --frozen-lockfile >/dev/null 2>&1 || pnpm install >/dev/null )
( cd "$SDK_DIR" && pnpm --filter @afauthhq/core --filter @afauthhq/server build >/dev/null )

mkdir -p "$VENDOR"
rm -f "$VENDOR"/afauthhq-core.tgz "$VENDOR"/afauthhq-server.tgz

# `pnpm pack` rewrites `workspace:*` to the concrete local version, so the
# packed server resolves @afauthhq/core to the core tarball we also vendor.
echo "[pack-sdk] packing tarballs into $VENDOR ..."
( cd "$SDK_DIR/packages/core"   && pnpm pack --pack-destination "$VENDOR" >/dev/null )
( cd "$SDK_DIR/packages/server" && pnpm pack --pack-destination "$VENDOR" >/dev/null )

# Normalise the version-stamped filenames to the stable names package.json references.
mv "$VENDOR"/afauthhq-core-*.tgz   "$VENDOR/afauthhq-core.tgz"
mv "$VENDOR"/afauthhq-server-*.tgz "$VENDOR/afauthhq-server.tgz"

echo "[pack-sdk] done:"
ls -1 "$VENDOR"
