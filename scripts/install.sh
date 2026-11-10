#!/bin/bash
# Installs the helper and the `bridge` CLI from build/bin (built by scripts/build.sh).
#
#   scripts/build.sh                 # first, as your user
#   sudo scripts/install.sh          # install / upgrade
#   sudo scripts/install.sh --uninstall
#
# Most people should use the app instead: build/Bridge.app installs the helper itself.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
  exec "$ROOT/scripts/install-helper.sh" --uninstall
fi
[ -x "$ROOT/build/bin/bridge-helper" ] || { echo "Run scripts/build.sh first (without sudo)." >&2; exit 1; }
exec "$ROOT/scripts/install-helper.sh" "$ROOT/build/bin"
