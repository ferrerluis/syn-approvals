#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    printf '%s\n' 'usage: package-macos-release.sh SYN_APP RELEASE_JSON REMOTE_SOURCE_ARCHIVE REMOTE_HELPER_BINARY OUTPUT_DIRECTORY' >&2
    exit 2
fi

app_dir=$1
release_json=$2
remote_source_archive=$3
remote_helper_binary=$4
output_dir=$5
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
release_tool="$repo_dir/scripts/release-tool.py"

test -d "$app_dir"
codesign --verify --strict --verbose=2 "$app_dir"
signature_details=$(codesign -d --verbose=4 "$app_dir" 2>&1)
ad_hoc=0
case "$signature_details" in
    *'Signature=adhoc'*)
        if [ "${SYN_ALLOW_ADHOC_PACKAGE_TEST:-0}" != 1 ]; then
            printf '%s\n' 'refusing to package an ad-hoc-signed release app' >&2
            exit 1
        fi
        ad_hoc=1
        ;;
    *'(runtime)'*) ;;
    *)
        printf '%s\n' 'release app is missing hardened runtime signing' >&2
        exit 1
        ;;
esac
if [ "$ad_hoc" = 0 ]; then
    if [ -z "${SYN_EXPECTED_SIGNER_SHA256:-}" ]; then
        printf '%s\n' 'packaging a release requires the expected signer fingerprint' >&2
        exit 1
    fi
    python3 "$release_tool" verify-macos-signature \
        --app "$app_dir" --expected-signer-sha256 "$SYN_EXPECTED_SIGNER_SHA256"
fi
python3 "$release_tool" validate --metadata "$release_json"
release_id=$(python3 "$release_tool" get --metadata "$release_json" --field release_id)
cmp "$release_json" "$app_dir/Contents/Resources/release.json"
test -f "$app_dir/Contents/Resources/remote-source.json"
bundled_source="$app_dir/Contents/Resources/$(basename -- "$remote_source_archive")"
test -f "$bundled_source"
cmp "$remote_source_archive" "$bundled_source"
python3 "$release_tool" validate-remote-source \
    --metadata "$release_json" \
    --remote-source "$app_dir/Contents/Resources/remote-source.json" \
    --artifact "$bundled_source"
test -f "$app_dir/Contents/Resources/remote-helper.json"
bundled_helper="$app_dir/Contents/Resources/$(basename -- "$remote_helper_binary")"
test -f "$bundled_helper"
cmp "$remote_helper_binary" "$bundled_helper"
python3 "$release_tool" validate-remote-helper \
    --metadata "$release_json" \
    --remote-helper "$app_dir/Contents/Resources/remote-helper.json" \
    --artifact "$bundled_helper"

mkdir -p "$output_dir"
archive="$output_dir/Syn-macOS-${release_id}.zip"
if [ -e "$archive" ] || [ -L "$archive" ]; then
    printf 'refusing to replace existing release artifact: %s\n' "$archive" >&2
    exit 1
fi
temporary_archive="$output_dir/.Syn-macOS-${release_id}.zip.incomplete.$$"
verification_dir=$(mktemp -d "${TMPDIR:-/tmp}/syn-package-verify.XXXXXX")
trap 'rm -f "$temporary_archive"; rm -rf "$verification_dir"' EXIT HUP INT TERM
ditto -c -k --sequesterRsrc --keepParent "$app_dir" "$temporary_archive"
ditto -x -k "$temporary_archive" "$verification_dir"
verified_app="$verification_dir/Syn.app"
test -d "$verified_app"
cmp "$release_json" "$verified_app/Contents/Resources/release.json"
python3 "$release_tool" validate-remote-source \
    --metadata "$release_json" \
    --remote-source "$verified_app/Contents/Resources/remote-source.json" \
    --artifact "$verified_app/Contents/Resources/$(basename -- "$remote_source_archive")"
python3 "$release_tool" validate-remote-helper \
    --metadata "$release_json" \
    --remote-helper "$verified_app/Contents/Resources/remote-helper.json" \
    --artifact "$verified_app/Contents/Resources/$(basename -- "$remote_helper_binary")"
if [ "$ad_hoc" = 0 ]; then
    python3 "$release_tool" verify-macos-signature \
        --app "$verified_app" --expected-signer-sha256 "$SYN_EXPECTED_SIGNER_SHA256"
else
    codesign --verify --strict --verbose=2 "$verified_app"
fi
if ! ln "$temporary_archive" "$archive"; then
    printf 'refusing to replace existing release artifact: %s\n' "$archive" >&2
    exit 1
fi
rm -f "$temporary_archive"
printf '%s\n' "$archive"
