#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/dist"}
build_dir="$repo_dir/macos/.build"
app_dir="$output_dir/Syn.app"

cd "$repo_dir/macos"
swift build -c release

rm -rf "$app_dir"
install -d "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
install -m 0755 "$build_dir/release/Syn" "$app_dir/Contents/MacOS/Syn"
install -m 0644 "$repo_dir/macos/Support/Info.plist" "$app_dir/Contents/Info.plist"
# SwiftPM can leave removed resources in an incremental build directory. Package
# only the declared artwork, never stale resources from an earlier build.
resource_dir="$app_dir/Contents/Resources/Syn_Syn.bundle"
install -d "$resource_dir"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-logo-color.png" "$resource_dir/"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-logo-black.svg" "$resource_dir/"

# AppKit misrenders the SVG texture. Downsample the supplied 1691px color PNG.
icon_work_dir=$(mktemp -d "${TMPDIR:-/tmp}/syn-icon.XXXXXX")
swift "$repo_dir/scripts/build-branding.swift" \
    "$repo_dir/assets/branding/color/syn-logo-color@4x.png" "$icon_work_dir/Syn.iconset"
iconutil -c icns "$icon_work_dir/Syn.iconset" -o "$app_dir/Contents/Resources/Syn.icns"

if [ -n "${SYN_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --options runtime --timestamp --sign "$SYN_CODESIGN_IDENTITY" "$app_dir"
else
    codesign --force --sign - "$app_dir"
fi
codesign --verify --strict --verbose=2 "$app_dir"
swift "$repo_dir/scripts/verify-branding-package.swift" "$app_dir"
printf '%s\n' "$app_dir"
