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
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-app-icon-light.png" "$resource_dir/"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-app-icon-dark.png" "$resource_dir/"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-menu-icon.svg" "$resource_dir/"

# Let Xcode compile the supplied Icon Composer source. Assets.car retains the
# light/dark Liquid Glass treatments; Syn.icns is the compatibility fallback.
icon_work_dir=$(mktemp -d "${TMPDIR:-/tmp}/syn-icon.XXXXXX")
xcrun actool \
    --compile "$icon_work_dir" \
    --platform macosx \
    --minimum-deployment-target 15.0 \
    --app-icon Syn \
    --output-partial-info-plist "$icon_work_dir/partial.plist" \
    --warnings --errors --notices \
    "$repo_dir/assets/branding/app-icon/Syn.icon"
install -m 0644 "$icon_work_dir/Assets.car" "$app_dir/Contents/Resources/Assets.car"
install -m 0644 "$icon_work_dir/Syn.icns" "$app_dir/Contents/Resources/Syn.icns"
xcrun assetutil --info "$app_dir/Contents/Resources/Assets.car" > "$icon_work_dir/assets.json"
grep -q '"Name" : "Syn"' "$icon_work_dir/assets.json"
grep -q '"Appearance" : "NSAppearanceNameDarkAqua"' "$icon_work_dir/assets.json"
grep -q '"PixelWidth" : 1024' "$icon_work_dir/assets.json"

if [ -n "${SYN_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --options runtime --timestamp --sign "$SYN_CODESIGN_IDENTITY" "$app_dir"
else
    codesign --force --sign - "$app_dir"
fi
codesign --verify --strict --verbose=2 "$app_dir"
# Exercise the real lookup from an independent app layout, not a standalone
# script that bypasses SynBranding. Link only branding code, never app services.
probe_work_dir=$(mktemp -d "${TMPDIR:-/tmp}/syn-branding-probe.XXXXXX")
probe_app="$probe_work_dir/Relocated/Syn.app"
install -d "$probe_app/Contents/MacOS"
cp "$app_dir/Contents/Info.plist" "$probe_app/Contents/Info.plist"
ditto "$app_dir/Contents/Resources" "$probe_app/Contents/Resources"
swiftc -parse-as-library -swift-version 6 -warnings-as-errors \
    -target "$(uname -m)-apple-macosx15.0" \
    "$repo_dir/macos/Sources/Syn/Branding.swift" \
    "$build_dir/release/Syn.build/DerivedSources/resource_bundle_accessor.swift" \
    "$repo_dir/scripts/verify-branding-package.swift" \
    -o "$probe_app/Contents/MacOS/Syn"
"$probe_app/Contents/MacOS/Syn"
# Leave the actual build-tree resources available: an accidental fallback to
# them must still fail this negative test instead of masking missing artwork.
mv "$probe_app/Contents/Resources/Syn_Syn.bundle" "$probe_work_dir/hidden-artwork.bundle"
"$probe_app/Contents/MacOS/Syn" --expect-missing
printf '%s\n' "$app_dir"
