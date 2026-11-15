#!/bin/bash
# Installs Bridge from this disk image into /Applications and removes the
# "downloaded from the internet" flag, so macOS opens it without the
# "Apple could not verify" warning. Bridge is free and not notarized by Apple.
#
# Run it from Terminal (works on every macOS version):
#   bash "/Volumes/Bridge/Install Bridge.command"
# The volume name includes the version, e.g. "/Volumes/Bridge 0.9.0"; drag this
# file into the Terminal window to paste its exact path.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$HERE/Bridge.app"
TARGET="/Applications/Bridge.app"

if [ ! -d "$SOURCE" ]; then
  echo "Bridge.app was not found next to this script ($HERE)." >&2
  exit 1
fi

echo "Installing Bridge into /Applications…"

# Quit a running copy first; tunnels keep running in the helper.
osascript -e 'tell application id "com.rtmo0.bridge" to quit' >/dev/null 2>&1 || true
sleep 1

SUDO=""
if [ ! -w /Applications ] || { [ -e "$TARGET" ] && [ ! -w "$TARGET" ]; }; then
  echo "Your password is needed to write to /Applications."
  SUDO="sudo"
fi

$SUDO rm -rf "$TARGET"
$SUDO ditto "$SOURCE" "$TARGET"
$SUDO xattr -dr com.apple.quarantine "$TARGET" 2>/dev/null || true

echo "Done. Opening Bridge — look for the VPN icon in the menu bar."
open "$TARGET"
