#!/bin/bash
# Installs the privileged helper from a folder containing the built binaries.
# Used by the app (Resources/install-helper.sh, run with administrator rights)
# and by scripts/install.sh.
#
#   install-helper.sh <source-dir> [version]   install / upgrade (version: app that installs it)
#   install-helper.sh --uninstall
#
# <source-dir> must contain bridge-helper and amneziawg-go; openvpn, xray, openconnect (with
# bridge-openconnect-auth) and bridge (CLI) are optional.

set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

LABEL="com.rtmo0.bridge.helper"
DEST="/Library/PrivilegedHelperTools/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
CLI="/usr/local/bin/bridge"
LOGDIR="/var/log/bridge"
SOCKET="/var/run/bridge/helper.sock"

[ "$(id -u)" = 0 ] || { echo "Must run as root." >&2; exit 1; }

# Unprivileged account the VPN backends run as (the helper keeps root only for
# interfaces, routes, firewall and DNS).
ACCOUNT="_bridge"

ensure_account() {
  local id=""
  if dscl . -read "/Groups/$ACCOUNT" PrimaryGroupID >/dev/null 2>&1; then
    id="$(dscl . -read "/Groups/$ACCOUNT" PrimaryGroupID | awk '{print $2}')"
  fi
  if dscl . -read "/Users/$ACCOUNT" UniqueID >/dev/null 2>&1; then
    [ -n "$id" ] || { echo "User $ACCOUNT exists without group $ACCOUNT" >&2; exit 1; }
    return
  fi
  if [ -z "$id" ]; then
    # A system id (below 500) that is free as both a user and a group id.
    local used
    used="$( { dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')"
    for candidate in $(seq 290 499); do
      if ! printf '%s\n' "$used" | grep -qx "$candidate"; then id="$candidate"; break; fi
    done
    [ -n "$id" ] || { echo "No free system id for $ACCOUNT" >&2; exit 1; }
    dscl . -create "/Groups/$ACCOUNT"
    dscl . -create "/Groups/$ACCOUNT" PrimaryGroupID "$id"
    dscl . -create "/Groups/$ACCOUNT" RealName "Bridge VPN backends"
    dscl . -create "/Groups/$ACCOUNT" Password '*'
  fi
  dscl . -create "/Users/$ACCOUNT"
  dscl . -create "/Users/$ACCOUNT" UniqueID "$id"
  dscl . -create "/Users/$ACCOUNT" PrimaryGroupID "$id"
  dscl . -create "/Users/$ACCOUNT" UserShell /usr/bin/false
  dscl . -create "/Users/$ACCOUNT" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$ACCOUNT" RealName "Bridge VPN backends"
  dscl . -create "/Users/$ACCOUNT" Password '*'
  dscl . -create "/Users/$ACCOUNT" IsHidden 1
  echo "Created account $ACCOUNT ($id)."
}

# Authorization right Bridge asks for when "ask for my password before tunnel changes"
# is on. Admin users only; the password is remembered for 5 minutes per app.
RIGHT="com.rtmo0.bridge.control"

register_right() {
  security authorizationdb write "$RIGHT" >/dev/null 2>&1 <<'PLIST' || echo "Warning: could not register $RIGHT" >&2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>class</key><string>user</string>
  <key>group</key><string>admin</string>
  <key>authenticate-user</key><true/>
  <key>allow-root</key><true/>
  <key>shared</key><false/>
  <key>timeout</key><integer>300</integer>
  <key>version</key><integer>1</integer>
  <key>comment</key><string>Bridge: change VPN tunnels while Bridge asks for a password.</string>
  <key>default-prompt</key>
  <dict>
    <key></key><string>Bridge wants to change your VPN tunnels.</string>
    <key>ru</key><string>Bridge хочет изменить ваши VPN-туннели.</string>
    <key>de</key><string>Bridge möchte Ihre VPN-Tunnel ändern.</string>
  </dict>
</dict>
</plist>
PLIST
}

remove_account() {
  dscl . -delete "/Users/$ACCOUNT" 2>/dev/null || true
  dscl . -delete "/Groups/$ACCOUNT" 2>/dev/null || true
}

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
  rm -rf "$DEST" /var/run/bridge /var/run/amneziawg "/Library/Application Support/$LABEL"
  remove_account
  security authorizationdb remove "$RIGHT" >/dev/null 2>&1 || true
  echo "Bridge helper uninstalled."
  exit 0
fi

SRC="${1:?usage: install-helper.sh <source-dir> | --uninstall}"
for f in bridge-helper amneziawg-go; do
  [ -f "$SRC/$f" ] || { echo "Missing $SRC/$f" >&2; exit 1; }
done

stop_daemon
ensure_account
register_right

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
for f in openconnect bridge-openconnect-auth; do
  if [ -f "$SRC/$f" ]; then
    install -o root -g wheel -m 755 "$SRC/$f" "$DEST/$f"
  else
    rm -f "$DEST/$f"
  fi
done
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
