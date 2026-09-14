#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/dist-e2e"}
release_tool="$repo_dir/scripts/release-tool.py"

for variable in SYN_E2E_PRODUCTION_ROOT SYN_RELEASE_METADATA \
    SYN_REMOTE_SOURCE_METADATA SYN_REMOTE_SOURCE_ARCHIVE \
    SYN_REMOTE_HELPER_METADATA SYN_REMOTE_HELPER_BINARY
do
    eval "value=\${$variable:-}"
    if [ -z "$value" ]; then
        printf 'building SynE2E requires %s\n' "$variable" >&2
        exit 1
    fi
done

production_root=$(CDPATH= cd -- "$SYN_E2E_PRODUCTION_ROOT" && pwd)
release_json=$(CDPATH= cd -- "$(dirname -- "$SYN_RELEASE_METADATA")" && pwd)/$(basename -- "$SYN_RELEASE_METADATA")
remote_source_json=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_SOURCE_METADATA")" && pwd)/$(basename -- "$SYN_REMOTE_SOURCE_METADATA")
remote_source_archive=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_SOURCE_ARCHIVE")" && pwd)/$(basename -- "$SYN_REMOTE_SOURCE_ARCHIVE")
remote_helper_json=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_HELPER_METADATA")" && pwd)/$(basename -- "$SYN_REMOTE_HELPER_METADATA")
remote_helper_binary=$(CDPATH= cd -- "$(dirname -- "$SYN_REMOTE_HELPER_BINARY")" && pwd)/$(basename -- "$SYN_REMOTE_HELPER_BINARY")

test -d "$production_root/macos/Sources/Syn/Resources/Branding"
test -f "$production_root/macos/Package.swift"

# Finish the exact-candidate checks before compiling or creating output. The
# harness comes from this checkout, but every production input comes from the
# clean checkout named by release.json.
python3 "$release_tool" validate --metadata "$release_json"
python3 "$release_tool" verify-checkout \
    --metadata "$release_json" \
    --repository "$production_root" \
    --source-input macos/Sources/Syn
python3 "$release_tool" validate-remote-source \
    --metadata "$release_json" \
    --remote-source "$remote_source_json" \
    --artifact "$remote_source_archive"
python3 "$release_tool" validate-remote-helper \
    --metadata "$release_json" \
    --remote-helper "$remote_helper_json" \
    --artifact "$remote_helper_binary"

app="$output_dir/SynE2E.app"
if [ -e "$app" ] || [ -L "$app" ]; then
    printf 'refusing to replace existing E2E app: %s\n' "$app" >&2
    exit 1
fi

if [ "${SYN_E2E_VALIDATE_ONLY:-0}" = 1 ]; then
    printf '%s\n' 'SynE2E candidate inputs verified'
    exit 0
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/syn-e2e-build.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
sources="$stage/Sources/SynE2E"
mkdir -p "$sources/Resources/Branding"

for source in "$production_root"/macos/Sources/Syn/*.swift; do
    [ "$(basename "$source")" = SynApp.swift ] && continue
    ln -s "$source" "$sources/$(basename "$source")"
done
ln -s "$repo_dir/macos/Tests/SynTests/E2ETestApprovalHarness.swift" "$sources/E2ETestApprovalHarness.swift"
ln -s "$repo_dir/macos/Tests/SynE2EApp/SynE2EApp.swift" "$sources/SynE2EApp.swift"
for resource in "$production_root"/macos/Sources/Syn/Resources/Branding/*; do
    install -m 0644 "$resource" "$sources/Resources/Branding/$(basename "$resource")"
done

cp "$production_root/macos/Package.swift" "$stage/Package.swift"
sed -i '' 's/name: "Syn"/name: "SynE2E"/g; s/targets: \["Syn"\]/targets: ["SynE2E"]/g; s/name: "SynTests"/name: "UnusedTests"/g; s/dependencies: \["Syn"\]/dependencies: ["SynE2E"]/g; s/path: "Sources\/Syn"/path: "Sources\/SynE2E"/g; s/path: "Tests\/SynTests"/path: "Tests\/UnusedTests"/g' "$stage/Package.swift"
mkdir -p "$stage/Tests/UnusedTests"
printf 'import Testing\n' > "$stage/Tests/UnusedTests/Placeholder.swift"
mkdir -p "$stage/Tests/UnusedTests/Fixtures"

swift build --package-path "$stage" --scratch-path "$stage/.build" -c release --product SynE2E
staged_app="$stage/SynE2E.app"
mkdir -p "$staged_app/Contents/MacOS" "$staged_app/Contents/Resources"
install -m 0755 "$stage/.build/release/SynE2E" "$staged_app/Contents/MacOS/SynE2E"
cp -R "$stage/.build/release/SynE2E_SynE2E.bundle" "$staged_app/Contents/Resources/"
install -m 0644 "$release_json" "$staged_app/Contents/Resources/release.json"
install -m 0644 "$remote_source_json" "$staged_app/Contents/Resources/remote-source.json"
install -m 0644 "$remote_source_archive" "$staged_app/Contents/Resources/$(basename -- "$remote_source_archive")"
install -m 0644 "$remote_helper_json" "$staged_app/Contents/Resources/remote-helper.json"
install -m 0555 "$remote_helper_binary" "$staged_app/Contents/Resources/$(basename -- "$remote_helper_binary")"
cat > "$staged_app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>SynE2E</string>
<key>CFBundleIdentifier</key><string>org.syn-approvals.SynE2E</string>
<key>CFBundleName</key><string>Syn E2E</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
</dict></plist>
PLIST

# SwiftPM signs its standalone executable before the harness adds the app bundle resources.
# Sign the complete bundle so the executable and every sealed resource belong to one valid app.
/usr/bin/codesign --force --sign - "$staged_app"
/usr/bin/codesign --verify --strict --deep --verbose=2 "$staged_app"

swift build --package-path "$production_root/macos" --scratch-path "$stage/production-build" -c release --product Syn
production="$stage/production-build/release/Syn"
if strings "$production" | grep -Eq 'E2EScenarioSigner|E2EDisposableKeyStore|SynE2EApp'; then
    printf '%s\n' 'shipping Syn unexpectedly contains E2E harness code' >&2
    exit 1
fi
/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$staged_app/Contents/Info.plist" | grep -qx 'org.syn-approvals.SynE2E'
cmp "$release_json" "$staged_app/Contents/Resources/release.json"
python3 "$release_tool" validate-remote-source \
    --metadata "$staged_app/Contents/Resources/release.json" \
    --remote-source "$staged_app/Contents/Resources/remote-source.json" \
    --artifact "$staged_app/Contents/Resources/$(basename -- "$remote_source_archive")"
python3 "$release_tool" validate-remote-helper \
    --metadata "$staged_app/Contents/Resources/release.json" \
    --remote-helper "$staged_app/Contents/Resources/remote-helper.json" \
    --artifact "$staged_app/Contents/Resources/$(basename -- "$remote_helper_binary")"
strings "$staged_app/Contents/MacOS/SynE2E" | grep -q 'E2EScenarioSigner'

python3 "$release_tool" verify-checkout \
    --metadata "$release_json" \
    --repository "$production_root" \
    --source-input macos/Sources/Syn

if [ "${SYN_E2E_FORCE_LATE_FAILURE:-0}" = 1 ]; then
    printf '%s\n' 'forced late SynE2E build failure' >&2
    exit 1
fi

mkdir -p "$output_dir"
if ! mv -n "$staged_app" "$app" || [ -e "$staged_app" ] || [ ! -d "$app" ]; then
    printf 'refusing to replace existing E2E app: %s\n' "$app" >&2
    exit 1
fi
printf '%s\n' "$app"
