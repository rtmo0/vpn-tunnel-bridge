#!/bin/bash
# Regenerates Resources/AppIcon.icns from scripts/make-icon.swift.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/build/icon"
SET="$WORK/AppIcon.iconset"
rm -rf "$SET"
mkdir -p "$SET" "$ROOT/Resources"
swift "$ROOT/scripts/make-icon.swift" "$WORK/AppIcon-1024.png"
for size in 16 32 128 256 512; do
  sips -z $size $size "$WORK/AppIcon-1024.png" --out "$SET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z $double $double "$WORK/AppIcon-1024.png" --out "$SET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$SET" -o "$ROOT/Resources/AppIcon.icns"
echo "wrote Resources/AppIcon.icns"
