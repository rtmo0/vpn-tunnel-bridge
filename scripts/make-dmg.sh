#!/bin/bash
# Packs build/Bridge.app into build/Bridge-<version>.dmg: the app, a link to
# Applications, an installer script that clears the quarantine flag (Bridge is
# not notarized) and a bilingual read-me. Run after scripts/build.sh.
#
#   scripts/make-dmg.sh
#
# Output: build/Bridge-<version>.dmg and build/Bridge-<version>.dmg.sha256

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/Bridge.app"
[ -d "$APP" ] || { echo "build/Bridge.app not found: run scripts/build.sh first" >&2; exit 1; }

VERSION="$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist")"
NAME="Bridge-$VERSION"
DMG="$ROOT/build/$NAME.dmg"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

ditto "$APP" "$STAGE/Bridge.app"
ln -s /Applications "$STAGE/Applications"
install -m 755 "$ROOT/scripts/dmg/Install Bridge.command" "$STAGE/Install Bridge.command"
# The read-me names the volume, which carries the version.
sed "s/Bridge 0\.9\.0/Bridge $VERSION/g" "$ROOT/scripts/dmg/Read Me.txt" > "$STAGE/Read Me.txt"

rm -f "$DMG"
hdiutil create -volname "Bridge $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null
(cd "$ROOT/build" && shasum -a 256 "$NAME.dmg" | awk '{print $1}' > "$NAME.dmg.sha256")

echo "==> $DMG"
echo "    sha256 $(cat "$DMG.sha256")"
