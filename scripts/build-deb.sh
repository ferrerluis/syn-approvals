#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_dir/dist"}
stage_dir=$(mktemp -d)
trap 'rm -rf "$stage_dir"' EXIT HUP INT TERM

if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != aarch64 ]; then
    printf '%s\n' 'build-deb.sh must run on Linux ARM64 so libpam and sudo ABI linking are real.' >&2
    exit 1
fi

cd "$repo_dir"
cargo build --locked --release --workspace

package_root="$stage_dir/syn-approvals"
install -d "$package_root/DEBIAN" "$package_root/usr/bin" "$package_root/usr/libexec/syn"
install -d "$package_root/usr/libexec/sudo" "$package_root/lib/systemd/system" "$package_root/etc/pam.d"
install -m 0644 packaging/debian/control "$package_root/DEBIAN/control"
install -m 0755 packaging/debian/postinst packaging/debian/prerm "$package_root/DEBIAN/"
install -m 0755 target/release/synctl "$package_root/usr/bin/synctl"
install -m 0755 target/release/syn-agent "$package_root/usr/libexec/syn/syn-agent"
install -m 0644 target/release/libsyn_approval.so "$package_root/usr/libexec/sudo/syn_approval.so"
install -m 0644 packaging/systemd/syn-agent.service "$package_root/lib/systemd/system/"
install -m 0644 packaging/systemd/syn-auto-recover.service "$package_root/lib/systemd/system/"
install -m 0644 packaging/pam/syn-sudo-fallback "$package_root/etc/pam.d/"

mkdir -p "$output_dir"
dpkg-deb --root-owner-group --build "$package_root" "$output_dir/syn-approvals_0.1.0~alpha1_arm64.deb"
dpkg-deb --info "$output_dir/syn-approvals_0.1.0~alpha1_arm64.deb"
