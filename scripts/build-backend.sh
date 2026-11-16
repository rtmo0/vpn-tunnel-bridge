#!/bin/bash
# Builds amneziawg-go from source as a universal (arm64 + x86_64) binary.
#
#   scripts/build-backend.sh            # pinned version
#   AWG_GO_VERSION=v3.1.x scripts/build-backend.sh
#
# Output: build/backend/amneziawg-go

set -euo pipefail

AWG_GO_VERSION="${AWG_GO_VERSION:-v3.1.20260828}"
AWG_GO_REPO="https://github.com/amnezia-vpn/amneziawg-go"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/build/src/amneziawg-go"
OUT="$ROOT/build/backend"

command -v go >/dev/null || { echo "Go is required: brew install go" >&2; exit 1; }

echo "==> Fetching amneziawg-go $AWG_GO_VERSION"
rm -rf "$SRC"
mkdir -p "$(dirname "$SRC")" "$OUT"
git clone --quiet --depth 1 --branch "$AWG_GO_VERSION" "$AWG_GO_REPO" "$SRC"

cd "$SRC"

# Bridge hands amneziawg-go a utun it created and configured (WG_TUN_FD) and runs it
# without root, so it must not try to set the MTU itself (that needs root).
sed -i '' 's/tun\.CreateTUNFromFile(file, device\.DefaultMTU)/tun.CreateTUNFromFile(file, 0)/' main.go
grep -q 'tun.CreateTUNFromFile(file, 0)' main.go || { echo "Could not patch main.go (MTU)" >&2; exit 1; }

for arch in arm64 amd64; do
  echo "==> Building for $arch"
  GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 \
    go build -trimpath -ldflags "-s -w" -o "$OUT/amneziawg-go-$arch" .
done

lipo -create -output "$OUT/amneziawg-go" "$OUT/amneziawg-go-arm64" "$OUT/amneziawg-go-amd64"
rm -f "$OUT/amneziawg-go-arm64" "$OUT/amneziawg-go-amd64"
codesign --force --sign - "$OUT/amneziawg-go" 2>/dev/null
# "+fd": built with the patch above; scripts/build.sh rebuilds older binaries.
echo "$AWG_GO_VERSION+fd" > "$OUT/amneziawg-go.version"

echo "==> $(lipo -info "$OUT/amneziawg-go")"
