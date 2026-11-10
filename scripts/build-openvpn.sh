#!/bin/bash
# Builds OpenVPN from the official release tarball.
# OpenSSL, LZ4 and LZO are linked statically (from Homebrew), so the binary only
# depends on system libraries and can safely run as root from a root-owned folder.
#
#   brew install openssl@3 lz4 lzo pkgconf
#   scripts/build-openvpn.sh
#
# Output: build/backend/openvpn (native architecture)

set -euo pipefail

# On GitHub Actions, surface failures as annotations (readable without log access).
annotate() {  # $1 = title, $2 = file or text
  [ -n "${GITHUB_ACTIONS:-}" ] || return 0
  local body
  if [ -f "$2" ]; then body="$(grep -iE 'error|not found|missing|undefined|fatal' "$2" | tail -25)"; [ -n "$body" ] || body="$(tail -25 "$2")"
  else body="$2"; fi
  body="${body//'%'/'%25'}"; body="${body//$'\r'/}"; body="${body//$'\n'/'%0A'}"
  echo "::error title=$1::$body"
}
trap 'annotate "build-openvpn.sh" "failed at line $LINENO: $BASH_COMMAND"' ERR

OPENVPN_VERSION="${OPENVPN_VERSION:-2.7.9}"
URL="https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN_VERSION/openvpn-$OPENVPN_VERSION.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/build/src"
OUT="$ROOT/build/backend"
mkdir -p "$SRC" "$OUT"

for pkg in openssl@3 lz4 lzo; do
  brew --prefix --installed "$pkg" >/dev/null 2>&1 || { echo "Missing $pkg: brew install $pkg" >&2; exit 1; }
done
SSL="$(brew --prefix openssl@3)"
LZ4="$(brew --prefix lz4)"
LZO="$(brew --prefix lzo)"

echo "==> Fetching OpenVPN $OPENVPN_VERSION"
rm -rf "$SRC/openvpn-$OPENVPN_VERSION"
curl -fsSL "$URL" -o "$SRC/openvpn-$OPENVPN_VERSION.tar.gz"
tar -xzf "$SRC/openvpn-$OPENVPN_VERSION.tar.gz" -C "$SRC"
cd "$SRC/openvpn-$OPENVPN_VERSION"

echo "==> Configuring"
./configure \
  --disable-dependency-tracking \
  --disable-plugins \
  --disable-pkcs11 \
  --disable-unit-tests \
  --disable-debug \
  --enable-lz4 --enable-lzo \
  OPENSSL_CFLAGS="-I$SSL/include" \
  OPENSSL_LIBS="$SSL/lib/libssl.a $SSL/lib/libcrypto.a" \
  LZ4_CFLAGS="-I$LZ4/include" LZ4_LIBS="$LZ4/lib/liblz4.a" \
  LZO_CFLAGS="-I$LZO/include" LZO_LIBS="$LZO/lib/liblzo2.a" \
  >"$SRC/openvpn-configure.log" 2>&1 || {
    tail -30 "$SRC/openvpn-configure.log"
    annotate "OpenVPN configure" "$SRC/openvpn-configure.log"
    annotate "OpenVPN config.log" config.log
    exit 1
  }

echo "==> Building"
make -j"$(sysctl -n hw.ncpu)" >"$SRC/openvpn-make.log" 2>&1 || {
  tail -30 "$SRC/openvpn-make.log"
  annotate "OpenVPN make" "$SRC/openvpn-make.log"
  exit 1
}

cp src/openvpn/openvpn "$OUT/openvpn"
strip -x "$OUT/openvpn"
codesign --force --sign - "$OUT/openvpn" 2>/dev/null
echo "$OPENVPN_VERSION" > "$OUT/openvpn.version"

if otool -L "$OUT/openvpn" | grep -q /opt/homebrew; then
  echo "ERROR: openvpn still links against Homebrew libraries:" >&2
  otool -L "$OUT/openvpn" >&2
  annotate "OpenVPN linking" "$(otool -L "$OUT/openvpn")"
  exit 1
fi
echo "==> $("$OUT/openvpn" --version | head -1)"
