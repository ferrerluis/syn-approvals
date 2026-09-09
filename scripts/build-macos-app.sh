#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/dist"}
build_dir="$repo_dir/macos/.build"
app_dir="$output_dir/Syn.app"
release_tool="$repo_dir/scripts/release-tool.py"

release_json=
remote_source_json=
remote_source_archive=
remote_helper_json=
remote_helper_binary=
if [ -n "${SYN_RELEASE_METADATA:-}" ]; then
    release_json=$(CDPATH= cd -- "$(dirname -- "$SYN_RELEASE_METADATA")" && pwd)/$(basename -- "$SYN_RELEASE_METADATA")
    python3 "$release_tool" validate --metadata "$release_json"
    SYN_RELEASE_ID=$(python3 "$release_tool" get --metadata "$release_json" --field release_id)
    SYN_RELEASE_COMMIT=$(python3 "$release_tool" get --metadata "$release_json" --field commit)
    export SYN_RELEASE_ID SYN_RELEASE_COMMIT
fi
if [ -n "${SYN_REMOTE_SOURCE_METADATA:-}" ]; then
    if [ -z "$release_json" ]; then
        printf '%s\n' 'remote source metadata requires SYN_RELEASE_METADATA' >&2
        exit 1
    fi
    remote_source_json=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_SOURCE_METADATA")" && pwd)/$(basename -- "$SYN_REMOTE_SOURCE_METADATA")
    python3 "$release_tool" validate-remote-source \
        --metadata "$release_json" --remote-source "$remote_source_json"
fi
if [ -n "${SYN_REMOTE_SOURCE_ARCHIVE:-}" ]; then
    if [ -z "$release_json" ] || [ -z "$remote_source_json" ]; then
        printf '%s\n' 'remote source archive requires release and source metadata' >&2
        exit 1
    fi
    remote_source_archive=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_SOURCE_ARCHIVE")" && pwd)/$(basename -- "$SYN_REMOTE_SOURCE_ARCHIVE")
fi
if [ -n "${SYN_REMOTE_HELPER_METADATA:-}" ]; then
    if [ -z "$release_json" ]; then
        printf '%s\n' 'remote helper metadata requires SYN_RELEASE_METADATA' >&2
        exit 1
    fi
    remote_helper_json=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_HELPER_METADATA")" && pwd)/$(basename -- "$SYN_REMOTE_HELPER_METADATA")
    python3 "$release_tool" validate-remote-helper \
        --metadata "$release_json" --remote-helper "$remote_helper_json"
fi
if [ -n "${SYN_REMOTE_HELPER_BINARY:-}" ]; then
    if [ -z "$release_json" ] || [ -z "$remote_helper_json" ]; then
        printf '%s\n' 'remote helper binary requires release and helper metadata' >&2
        exit 1
    fi
    remote_helper_binary=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_HELPER_BINARY")" && pwd)/$(basename -- "$SYN_REMOTE_HELPER_BINARY")
fi
if [ -n "${SYN_MAC_BUILD_NUMBER:-}" ]; then
    python3 "$release_tool" validate-mac-build --value "$SYN_MAC_BUILD_NUMBER" >/dev/null
fi
if [ "${SYN_RELEASE_MODE:-0}" = 1 ]; then
    if [ -z "$release_json" ] || [ -z "$remote_source_json" ] || [ -z "$remote_source_archive" ] || \
       [ -z "$remote_helper_json" ] || [ -z "$remote_helper_binary" ] || \
       [ -z "${SYN_MAC_BUILD_NUMBER:-}" ] || [ -z "${SYN_CODESIGN_IDENTITY:-}" ] || \
       [ -z "${SYN_EXPECTED_SIGNER_SHA256:-}" ]; then
        printf '%s\n' 'release mode requires release/source metadata and archive, Mac build number, signing identity, and expected signer fingerprint' >&2
        exit 1
    fi
    if [ "$SYN_CODESIGN_IDENTITY" = - ]; then
        printf '%s\n' 'release mode refuses ad-hoc signing' >&2
        exit 1
    fi
fi
if [ -n "$release_json" ]; then
    if [ -z "$remote_source_json" ] || [ -z "$remote_source_archive" ] || \
       [ -z "$remote_helper_json" ] || [ -z "$remote_helper_binary" ]; then
        printf '%s\n' 'release metadata requires matching remote source and helper artifacts' >&2
        exit 1
    fi
    python3 "$release_tool" verify-checkout \
        --metadata "$release_json" \
        --repository "$repo_dir" \
        --source-input macos/Sources/Syn
    python3 "$release_tool" validate-remote-source \
        --metadata "$release_json" \
        --remote-source "$remote_source_json" \
        --artifact "$remote_source_archive"
    python3 "$release_tool" validate-remote-helper \
        --metadata "$release_json" \
        --remote-helper "$remote_helper_json" \
        --artifact "$remote_helper_binary"
fi

cd "$repo_dir/macos"
swift build -c release

rm -rf "$app_dir"
install -d "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
install -m 0755 "$build_dir/release/Syn" "$app_dir/Contents/MacOS/Syn"
install -m 0644 "$repo_dir/macos/Support/Info.plist" "$app_dir/Contents/Info.plist"
if [ -n "${SYN_MAC_BUILD_NUMBER:-}" ]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $SYN_MAC_BUILD_NUMBER" "$app_dir/Contents/Info.plist"
fi
if [ -n "$release_json" ]; then
    install -m 0644 "$release_json" "$app_dir/Contents/Resources/release.json"
fi
if [ -n "$remote_source_json" ]; then
    install -m 0644 "$remote_source_json" "$app_dir/Contents/Resources/remote-source.json"
fi
if [ -n "$remote_source_archive" ]; then
    install -m 0644 "$remote_source_archive" "$app_dir/Contents/Resources/$(basename -- "$remote_source_archive")"
fi
if [ -n "$remote_helper_json" ]; then
    install -m 0644 "$remote_helper_json" "$app_dir/Contents/Resources/remote-helper.json"
fi
if [ -n "$remote_helper_binary" ]; then
    install -m 0555 "$remote_helper_binary" "$app_dir/Contents/Resources/$(basename -- "$remote_helper_binary")"
fi
# SwiftPM can leave removed resources in an incremental build directory. Package
# only the declared artwork, never stale resources from an earlier build.
resource_dir="$app_dir/Contents/Resources/Syn_Syn.bundle"
install -d "$resource_dir"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-app-icon-light.png" "$resource_dir/"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-app-icon-dark.png" "$resource_dir/"
install -m 0644 "$build_dir/release/Syn_Syn.bundle/syn-menu-icon.svg" "$resource_dir/"

# Build independent light/dark ICNS files from the smallest exports that exceed
# macOS's 1024px maximum. The app switches its running Dock icon by appearance.
icon_work_dir=$(mktemp -d "${TMPDIR:-/tmp}/syn-icon.XXXXXX")
swift "$repo_dir/scripts/build-branding.swift" \
    "$repo_dir/assets/branding/light/syn-app-icon-light@2x.png" "$icon_work_dir/Syn.iconset"
iconutil -c icns "$icon_work_dir/Syn.iconset" -o "$app_dir/Contents/Resources/Syn.icns"
swift "$repo_dir/scripts/build-branding.swift" \
    "$repo_dir/assets/branding/dark/syn-app-icon-dark@2x.png" "$icon_work_dir/Syn-dark.iconset"
iconutil -c icns "$icon_work_dir/Syn-dark.iconset" -o "$app_dir/Contents/Resources/Syn-dark.icns"

if [ -n "${SYN_CODESIGN_IDENTITY:-}" ] && [ "${SYN_CODESIGN_TIMESTAMP:-apple}" = none ]; then
    codesign --force --options runtime --sign "$SYN_CODESIGN_IDENTITY" "$app_dir"
elif [ -n "${SYN_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --options runtime --timestamp --sign "$SYN_CODESIGN_IDENTITY" "$app_dir"
else
    codesign --force --sign - "$app_dir"
fi
codesign --verify --strict --verbose=2 "$app_dir"
if [ "${SYN_RELEASE_MODE:-0}" = 1 ]; then
    python3 "$release_tool" verify-macos-signature \
        --app "$app_dir" --expected-signer-sha256 "$SYN_EXPECTED_SIGNER_SHA256"
fi
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
    "$repo_dir/macos/Tests/SynTests/IconComparison.swift" \
    "$build_dir/release/Syn.build/DerivedSources/resource_bundle_accessor.swift" \
    "$repo_dir/scripts/verify-branding-package.swift" \
    -o "$probe_app/Contents/MacOS/Syn"
"$probe_app/Contents/MacOS/Syn"
# Leave the actual build-tree resources available: an accidental fallback to
# them must still fail this negative test instead of masking missing artwork.
mv "$probe_app/Contents/Resources/Syn_Syn.bundle" "$probe_work_dir/hidden-artwork.bundle"
"$probe_app/Contents/MacOS/Syn" --expect-missing
printf '%s\n' "$app_dir"
