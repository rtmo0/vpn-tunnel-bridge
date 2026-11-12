#!/bin/bash
# Builds OpenConnect from the official release tarball:
#   build/backend/openconnect               the tunnel (run by the helper as root)
#   build/backend/bridge-openconnect-auth   the login helper Bridge.app runs as the user
#                                           (libopenconnect: forms, SSO, server certificates)
# OpenSSL and LZ4 are linked statically (from Homebrew); libxml2 and zlib come from macOS.
#
#   brew install openssl@3 lz4 pkgconf
#   scripts/build-openconnect.sh
#
# Output: native architecture, like OpenVPN.

set -euo pipefail

annotate() {  # $1 = title, $2 = file or text
  [ -n "${GITHUB_ACTIONS:-}" ] || return 0
  local body
  if [ -f "$2" ]; then body="$(grep -iE 'error|not found|missing|undefined|fatal' "$2" | tail -25)"; [ -n "$body" ] || body="$(tail -25 "$2")"
  else body="$2"; fi
  body="${body//'%'/'%25'}"; body="${body//$'\r'/}"; body="${body//$'\n'/'%0A'}"
  echo "::error title=$1::$body"
}
trap 'annotate "build-openconnect.sh" "failed at line $LINENO: $BASH_COMMAND"' ERR

OPENCONNECT_VERSION="${OPENCONNECT_VERSION:-9.21}"
OPENCONNECT_SHA256="${OPENCONNECT_SHA256:-5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58}"
URL="https://www.infradead.org/openconnect/download/openconnect-$OPENCONNECT_VERSION.tar.gz"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/build/src"
OUT="$ROOT/build/backend"
mkdir -p "$SRC" "$OUT"

for pkg in openssl@3 lz4; do
  brew --prefix --installed "$pkg" >/dev/null 2>&1 || { echo "Missing $pkg: brew install $pkg" >&2; exit 1; }
done
SSL="$(brew --prefix openssl@3)"
LZ4="$(brew --prefix lz4)"
SDK="$(xcrun --show-sdk-path)"

echo "==> Fetching OpenConnect $OPENCONNECT_VERSION"
TARBALL="$SRC/openconnect-$OPENCONNECT_VERSION.tar.gz"
curl -fsSL "$URL" -o "$TARBALL"
echo "$OPENCONNECT_SHA256  $TARBALL" | shasum -a 256 -c - >/dev/null || {
  echo "Checksum mismatch for $TARBALL" >&2
  exit 1
}
rm -rf "$SRC/openconnect-$OPENCONNECT_VERSION"
tar -xzf "$TARBALL" -C "$SRC"
cd "$SRC/openconnect-$OPENCONNECT_VERSION"

STATIC="$SRC/static-libs-openconnect"
rm -rf "$STATIC"
mkdir -p "$STATIC"
cp "$SSL/lib/libssl.a" "$SSL/lib/libcrypto.a" "$LZ4/lib/liblz4.a" "$STATIC/"

echo "==> Configuring"
./configure \
  --disable-dependency-tracking \
  --disable-shared --enable-static \
  --disable-nls --disable-docs \
  --without-gnutls --with-openssl \
  --without-libproxy --without-stoken --without-libpskc --without-libpcsclite --without-gssapi \
  --with-builtin-json \
  --with-external-browser=no \
  --with-vpnc-script=/usr/bin/false \
  LDFLAGS="-L$STATIC" \
  OPENSSL_CFLAGS="-I$SSL/include" OPENSSL_LIBS="-lssl -lcrypto" \
  LIBLZ4_CFLAGS="-I$LZ4/include" LIBLZ4_LIBS="-llz4" \
  LIBXML2_CFLAGS="-I$SDK/usr/include/libxml2" LIBXML2_LIBS="-lxml2" \
  ZLIB_CFLAGS="" ZLIB_LIBS="-lz" \
  >"$SRC/openconnect-configure.log" 2>&1 || {
    tail -30 "$SRC/openconnect-configure.log"
    annotate "OpenConnect configure" "$SRC/openconnect-configure.log"
    annotate "OpenConnect config.log" config.log
    exit 1
  }

echo "==> Building"
make -j"$(sysctl -n hw.ncpu)" >"$SRC/openconnect-make.log" 2>&1 || {
  tail -30 "$SRC/openconnect-make.log"
  annotate "OpenConnect make" "$SRC/openconnect-make.log"
  exit 1
}

cp openconnect "$OUT/openconnect"

echo "==> Building bridge-openconnect-auth"
LIBS_EXTRA="$(sed -n 's/^LIBS = //p' Makefile)"
cc -O2 -Wall -I. -o "$OUT/bridge-openconnect-auth" "$ROOT/native/openconnect-auth/openconnect-auth.c" \
  .libs/libopenconnect.a -L"$STATIC" -lssl -lcrypto -llz4 -lxml2 -lz -liconv \
  -framework Security -framework CoreFoundation -framework SystemConfiguration $LIBS_EXTRA \
  >"$SRC/openconnect-auth.log" 2>&1 || {
    cat "$SRC/openconnect-auth.log"
    annotate "bridge-openconnect-auth" "$SRC/openconnect-auth.log"
    exit 1
  }

for f in openconnect bridge-openconnect-auth; do
  strip -x "$OUT/$f"
  codesign --force --sign - "$OUT/$f" 2>/dev/null
  if otool -L "$OUT/$f" | grep -q -e /opt/homebrew -e /usr/local/opt; then
    echo "ERROR: $f still links against Homebrew libraries:" >&2
    otool -L "$OUT/$f" >&2
    annotate "OpenConnect linking" "$(otool -L "$OUT/$f")"
    exit 1
  fi
done
echo "$OPENCONNECT_VERSION" > "$OUT/openconnect.version"
echo "==> $("$OUT/openconnect" --version 2>&1 | head -1)"
