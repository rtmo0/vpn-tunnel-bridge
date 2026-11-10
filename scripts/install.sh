#!/bin/bash
# Installs the privileged helper (launchd daemon) and the `bridge` CLI.
#
#   scripts/build.sh                 # first, as your user
#   sudo scripts/install.sh          # install / upgrade
#   sudo scripts/install.sh --uninstall
#
# Installed files (all owned by root):
#   /Library/PrivilegedHelperTools/com.rtmo0.bridge.helper/{bridge-helper,amneziawg-go}
#   /Library/LaunchDaemons/com.rtmo0.bridge.helper.plist
#   /usr/local/bin/bridge
# Logs: /var/log/bridge/

set -euo pipefail

LABEL="com.rtmo0.bridge.helper"
DEST="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
CLI="/usr/local/bin/bridge"
LOGDIR="/var/log/bridge"

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/bin"

stop_daemon() {
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    # SIGTERM makes the helper disconnect every tunnel before exiting.
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    for _ in $(seq 1 50); do
      launchctl print "system/$LABEL" >/dev/null 2>&1 || break
      sleep 0.1
    done
  fi
}

if [ "${1:-}" = "--uninstall" ]; then
  stop_daemon
  rm -f "$PLIST" "$CLI"
  rm -rf "$DEST" /var/run/bridge
  echo "Bridge uninstalled. Logs kept in $LOGDIR; your configs in ~/Library/Application Support/Bridge."
  exit 0
fi

for f in bridge bridge-helper amneziawg-go; do
  [ -x "$BIN/$f" ] || { echo "Missing $BIN/$f. Run scripts/build.sh first (without sudo)." >&2; exit 1; }
done

stop_daemon

install -d -o root -g wheel -m 755 "$DEST" "$LOGDIR" /usr/local/bin
install -o root -g wheel -m 755 "$BIN/bridge-helper" "$DEST/bridge-helper"
install -o root -g wheel -m 755 "$BIN/amneziawg-go" "$DEST/amneziawg-go"
install -o root -g wheel -m 755 "$BIN/bridge" "$CLI"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>$DEST/bridge-helper</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ExitTimeOut</key><integer>15</integer>
  <key>StandardOutPath</key><string>$LOGDIR/helper.log</string>
  <key>StandardErrorPath</key><string>$LOGDIR/helper.log</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null

launchctl bootstrap system "$PLIST"

for _ in $(seq 1 50); do
  [ -S /var/run/bridge/helper.sock ] && break
  sleep 0.1
done
if [ -S /var/run/bridge/helper.sock ]; then
  echo "Bridge installed. Try: bridge import <file.conf> && bridge up <name>"
else
  echo "Installed, but the helper did not start. See $LOGDIR/helper.log" >&2
  exit 1
fi
