#!/bin/bash
# Builds everything and assembles build/Bridge.app. Run as your normal user.
#
#   scripts/build.sh
#
# Output:
#   build/Bridge.app          the app (installs its helper on first launch)
#   build/bin/                CLI, helper and backends (for scripts/install.sh)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/bin"
APP="$ROOT/build/Bridge.app"
# Version: $VERSION, else the latest git tag (v1.2.3 -> 1.2.3), else 0.0.0.
VERSION="${VERSION:-$(git -C "$ROOT" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
VERSION="${VERSION:-0.0.0}"

if [ "$(id -u)" = 0 ]; then
  echo "Run scripts/build.sh as your normal user." >&2
  exit 1
fi

if [ ! -x "$ROOT/build/backend/amneziawg-go" ]; then
  "$ROOT/scripts/build-backend.sh"
fi
if [ ! -x "$ROOT/build/backend/openvpn" ]; then
  echo "NOTE: build/backend/openvpn not found; building without OpenVPN. Run scripts/build-openvpn.sh to add it."
fi
if [ ! -x "$ROOT/build/backend/openconnect" ]; then
  echo "NOTE: build/backend/openconnect not found; building without OpenConnect. Run scripts/build-openconnect.sh to add it."
fi
if [ ! -x "$ROOT/build/backend/xray" ]; then
  echo "NOTE: build/backend/xray not found; building without VLESS. Run scripts/build-xray.sh to add it."
fi

echo "==> Building Swift targets"
cd "$ROOT"
swift build -c release --arch arm64 --arch x86_64 2>&1 | grep -vE '^\[[0-9]+/[0-9]+\]|x86_64 architecture is deprecated' || true
PRODUCTS="$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)"
[ -x "$PRODUCTS/BridgeApp" ] || { echo "Swift build failed" >&2; exit 1; }

echo "==> Collecting binaries"
rm -rf "$BIN"
mkdir -p "$BIN"
cp "$PRODUCTS/bridge" "$PRODUCTS/bridge-helper" "$ROOT/build/backend/amneziawg-go" "$BIN/"
[ -x "$ROOT/build/backend/openvpn" ] && cp "$ROOT/build/backend/openvpn" "$BIN/"
[ -x "$ROOT/build/backend/xray" ] && cp "$ROOT/build/backend/xray" "$BIN/"
for f in openconnect bridge-openconnect-auth; do
  [ -x "$ROOT/build/backend/$f" ] && cp "$ROOT/build/backend/$f" "$BIN/"
done
for f in "$BIN"/*; do codesign --force --sign - "$f" 2>/dev/null; done
# Hardened runtime for our own binaries: bridge-helper also runs as root as OpenVPN's and
# OpenConnect's hook, so dyld must ignore DYLD_* variables in the environment it is given.
for f in bridge-helper bridge; do codesign --force --options runtime --sign - "$BIN/$f"; done

echo "==> Assembling Bridge.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$PRODUCTS/BridgeApp" "$APP/Contents/MacOS/Bridge"
cp "$BIN"/* "$APP/Contents/Resources/"
install -m 755 "$ROOT/scripts/install-helper.sh" "$APP/Contents/Resources/install-helper.sh"
cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>Bridge</string>
  <key>CFBundleIdentifier</key><string>com.rtmo0.bridge</string>
  <key>CFBundleName</key><string>Bridge</string>
  <key>CFBundleDisplayName</key><string>Bridge</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$(date +%Y%m%d%H%M)</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>BridgeUpdateRepository</key><string>rtmo0/vpn-tunnel-bridge</string>
  <key>NSHumanReadableCopyright</key><string>Copyright © 2026 Andrey Samarin. MIT License.</string>
</dict>
</plist>
PLIST

for f in "$APP/Contents/Resources"/*; do
  [ -x "$f" ] && [ "${f##*.}" != "sh" ] || continue
  case "$(basename "$f")" in
    bridge-helper|bridge) codesign --force --options runtime --sign - "$f" ;;
    *) codesign --force --sign - "$f" 2>/dev/null ;;
  esac
done
codesign --force --sign - "$APP"
codesign --verify "$APP"

echo "==> Done"
for f in "$APP/Contents/MacOS/Bridge" "$APP/Contents/Resources"/*; do
  case "${f##*.}" in sh|icns) continue;; esac
  echo "    $(basename "$f"): $(lipo -archs "$f")"
done
echo "Run it: open \"$APP\""
