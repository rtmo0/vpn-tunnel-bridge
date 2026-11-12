#!/bin/bash
# Builds Xray-core (the VLESS backend) from source as a universal (arm64 + x86_64) binary.
#
#   scripts/build-xray.sh               # pinned version
#   XRAY_VERSION=v26.x.y scripts/build-xray.sh
#
# Output: build/backend/xray

set -euo pipefail

XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"
XRAY_REPO="https://github.com/XTLS/Xray-core"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/build/src/xray-core"
OUT="$ROOT/build/backend"

command -v go >/dev/null || { echo "Go is required: brew install go" >&2; exit 1; }

echo "==> Fetching Xray-core $XRAY_VERSION"
rm -rf "$SRC"
mkdir -p "$(dirname "$SRC")" "$OUT"
git clone --quiet --depth 1 --branch "$XRAY_VERSION" "$XRAY_REPO" "$SRC"

cd "$SRC"
for arch in arm64 amd64; do
  echo "==> Building for $arch"
  GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w -buildid=" -o "$OUT/xray-$arch" ./main
done

lipo -create -output "$OUT/xray" "$OUT/xray-arm64" "$OUT/xray-amd64"
rm -f "$OUT/xray-arm64" "$OUT/xray-amd64"
codesign --force --sign - "$OUT/xray" 2>/dev/null
echo "$XRAY_VERSION" > "$OUT/xray.version"

echo "==> $(lipo -info "$OUT/xray")"
