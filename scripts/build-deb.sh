#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/dist"}
stage_dir=$(mktemp -d)
trap 'rm -rf "$stage_dir"' EXIT HUP INT TERM
release_tool="$repo_dir/scripts/release-tool.py"
target_dir=${CARGO_TARGET_DIR:-"$repo_dir/target"}
rust_tool=${SYN_CARGO:-cargo}
case "$rust_tool" in
    /*) ;;
    *)
        if ! rust_tool=$(command -v "$rust_tool"); then
            printf '%s\n' 'Cargo is unavailable; use the guided dependency installation before building.' >&2
            exit 1
        fi
        ;;
esac
if [ -z "$rust_tool" ] || [ ! -x "$rust_tool" ]; then
    printf '%s\n' 'Cargo must be executable.' >&2
    exit 1
fi
case "$target_dir" in
    /*) ;;
    *) target_dir="$repo_dir/$target_dir" ;;
esac

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != aarch64 ]; then
    printf '%s\n' 'build-deb.sh must run on Linux ARM64 so libpam and sudo ABI linking are real.' >&2
    exit 1
fi

package_version=0.1.0~alpha1
package_filename=syn-approvals_0.1.0~alpha1_arm64.deb
release_json=
if [ -n "${SYN_RELEASE_METADATA:-}" ]; then
    release_json=$(CDPATH= cd -- "$(dirname -- "$SYN_RELEASE_METADATA")" && pwd)/$(basename -- "$SYN_RELEASE_METADATA")
    python3 "$release_tool" validate --metadata "$release_json"
    SYN_RELEASE_ID=$(python3 "$release_tool" get --metadata "$release_json" --field release_id)
    SYN_RELEASE_COMMIT=$(python3 "$release_tool" get --metadata "$release_json" --field commit)
    export SYN_RELEASE_ID SYN_RELEASE_COMMIT
    package_version=$SYN_RELEASE_ID
    package_filename="syn-approvals_${SYN_RELEASE_ID}_arm64.deb"
fi

cd "$repo_dir"
if [ -n "$release_json" ]; then
    "$rust_tool" build --locked --frozen --offline --release --workspace
    python3 "$repo_dir/scripts/verify-linux-helper.py" \
        --binary "$target_dir/release/synctl" --metadata "$release_json"
else
    "$rust_tool" build --locked --release --workspace
fi

package_root="$stage_dir/syn-approvals"
install -d "$package_root/DEBIAN" "$package_root/usr/bin" "$package_root/usr/libexec/syn"
install -d "$package_root/usr/libexec/sudo" "$package_root/lib/systemd/system" "$package_root/etc/pam.d"
sed "s/^Version: .*/Version: $package_version/" packaging/debian/control > "$package_root/DEBIAN/control"
install -m 0755 packaging/debian/postinst packaging/debian/prerm "$package_root/DEBIAN/"
install -m 0755 "$target_dir/release/synctl" "$package_root/usr/bin/synctl"
install -m 0755 "$target_dir/release/syn-agent" "$package_root/usr/libexec/syn/syn-agent"
install -m 0644 "$target_dir/release/libsyn_approval.so" "$package_root/usr/libexec/sudo/syn_approval.so"
install -m 0644 packaging/systemd/syn-agent.service "$package_root/lib/systemd/system/"
install -m 0644 packaging/systemd/syn-auto-recover.service "$package_root/lib/systemd/system/"
install -m 0644 packaging/pam/syn-sudo-fallback "$package_root/etc/pam.d/"
if [ -n "$release_json" ]; then
    install -d "$package_root/usr/share/syn"
    install -m 0644 "$release_json" "$package_root/usr/share/syn/release.json"
fi

mkdir -p "$output_dir"
package_output="$output_dir/$package_filename"
if [ -n "$release_json" ]; then
    if [ -e "$package_output" ] || [ -L "$package_output" ]; then
        printf 'refusing to replace existing release artifact: %s\n' "$package_output" >&2
        exit 1
    fi
    temporary_package="$output_dir/.${package_filename}.incomplete.$$"
    trap 'rm -rf "$stage_dir"; rm -f "$temporary_package"' EXIT HUP INT TERM
    dpkg-deb --root-owner-group --build "$package_root" "$temporary_package"
    if ! ln "$temporary_package" "$package_output"; then
        printf 'refusing to replace existing release artifact: %s\n' "$package_output" >&2
        exit 1
    fi
    rm -f "$temporary_package"
else
    dpkg-deb --root-owner-group --build "$package_root" "$package_output"
fi
dpkg-deb --info "$package_output"
if [ "$(dpkg-deb -f "$package_output" Version)" != "$package_version" ]; then
    printf '%s\n' 'built Debian package version does not match release metadata' >&2
    exit 1
fi
