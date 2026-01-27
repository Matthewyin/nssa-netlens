#!/bin/bash
ICONset="frontend/build/icon.iconset"
mkdir -p "$ICONset"
SVG="frontend/public/icon.svg"

# Sizes
for size in 16 32 64 128 256 512; do
  rsvg-convert -w $size -h $size "$SVG" -o "$ICONset/icon_${size}x${size}.png"
  rsvg-convert -w $((size*2)) -h $((size*2)) "$SVG" -o "$ICONset/icon_${size}x${size}@2x.png"
done

iconutil -c icns "$ICONset" -o "frontend/build/icon.icns"
rm -rf "$ICONset"
echo "Generated frontend/build/icon.icns"
