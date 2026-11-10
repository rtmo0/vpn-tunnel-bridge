#!/bin/bash
# Builds Bridge (CLI + helper) in release mode, plus the backend if missing.
# Run as your normal user, not with sudo.
#
# Output: build/bin/{bridge,bridge-helper,amneziawg-go}

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/bin"

if [ "$(id -u)" = 0 ]; then
  echo "Run scripts/build.sh as your normal user (only install.sh needs sudo)." >&2
  exit 1
fi

if [ ! -x "$ROOT/build/backend/amneziawg-go" ]; then
  "$ROOT/scripts/build-backend.sh"
fi

echo "==> Building Bridge"
cd "$ROOT"
swift build -c release --arch arm64 --arch x86_64
PRODUCTS="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"

mkdir -p "$BIN"
cp "$PRODUCTS/bridge" "$PRODUCTS/bridge-helper" "$BIN/"
cp "$ROOT/build/backend/amneziawg-go" "$BIN/"
for f in "$BIN"/*; do codesign --force --sign - "$f" 2>/dev/null; done

echo "==> Built:"
for f in "$BIN"/*; do echo "    $(basename "$f"): $(lipo -archs "$f")"; done
echo "Next: sudo scripts/install.sh"
