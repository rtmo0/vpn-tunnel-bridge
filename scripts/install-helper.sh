#!/bin/bash
# Installs the privileged helper from a folder containing the built binaries.
# Used by the app (Resources/install-helper.sh, run with administrator rights)
# and by scripts/install.sh.
#
#   install-helper.sh <source-dir> [version]   install / upgrade (version: app that installs it)
#   install-helper.sh --uninstall
#
# <source-dir> must contain bridge-helper and amneziawg-go; openvpn, xray and bridge (CLI) are optional.

set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

LABEL="com.rtmo0.bridge.helper"
DEST="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
CLI="/usr/local/bin/bridge"
LOGDIR="/var/log/bridge"
SOCKET="/var/run/bridge/helper.sock"

[ "$(id -u)" = 0 ] || { echo "Must run as root." >&2; exit 1; }

stop_daemon() {
  if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    # SIGTERM makes the helper disconnect every tunnel before exiting.
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    for _ in $(seq 1 100); do
      launchctl print "system/$LABEL" >/dev/null 2>&1 || break
      sleep 0.1
    done
  fi
}

if [ "${1:-}" = "--uninstall" ]; then
  stop_daemon
  rm -f "$PLIST" "$CLI"
  rm -rf "$DEST" /var/run/bridge
  echo "Bridge helper uninstalled."
  exit 0
fi

SRC="${1:?usage: install-helper.sh <source-dir> | --uninstall}"
for f in bridge-helper amneziawg-go; do
  [ -f "$SRC/$f" ] || { echo "Missing $SRC/$f" >&2; exit 1; }
done

stop_daemon

install -d -o root -g wheel -m 755 "$DEST" "$LOGDIR" /usr/local/bin
install -o root -g wheel -m 755 "$SRC/bridge-helper" "$DEST/bridge-helper"
install -o root -g wheel -m 755 "$SRC/amneziawg-go" "$DEST/amneziawg-go"
if [ -f "$SRC/openvpn" ]; then
  install -o root -g wheel -m 755 "$SRC/openvpn" "$DEST/openvpn"
else
  rm -f "$DEST/openvpn"
fi
if [ -f "$SRC/xray" ]; then
  install -o root -g wheel -m 755 "$SRC/xray" "$DEST/xray"
else
  rm -f "$DEST/xray"
fi
if [ -n "${2:-}" ]; then
  printf '%s\n' "$2" > "$DEST/version"
  chown root:wheel "$DEST/version"
  chmod 644 "$DEST/version"
else
  rm -f "$DEST/version"
fi
if [ -f "$SRC/bridge" ]; then
  install -o root -g wheel -m 755 "$SRC/bridge" "$CLI"
fi

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
  <key>ExitTimeOut</key><integer>20</integer>
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
  [ -S "$SOCKET" ] && break
  sleep 0.1
done
if [ -S "$SOCKET" ]; then
  echo "Bridge helper installed."
else
  echo "Installed, but the helper did not start. See $LOGDIR/helper.log" >&2
  exit 1
fi
