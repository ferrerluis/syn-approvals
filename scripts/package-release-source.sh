#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf '%s\n' 'usage: package-release-source.sh REPOSITORY RELEASE_JSON OUTPUT_DIRECTORY' >&2
    exit 2
fi

repo_dir=$(CDPATH= cd -- "$1" && pwd)
release_json=$2
output_dir=$3
release_tool="$repo_dir/scripts/release-tool.py"

python3 "$release_tool" validate --metadata "$release_json"
release_id=$(python3 "$release_tool" get --metadata "$release_json" --field release_id)
release_commit=$(python3 "$release_tool" get --metadata "$release_json" --field commit)
head_commit=$(git -C "$repo_dir" rev-parse HEAD)
if [ "$head_commit" != "$release_commit" ]; then
    printf '%s\n' 'release metadata commit does not match the checked-out commit' >&2
    exit 1
fi
if ! git -C "$repo_dir" diff --quiet || ! git -C "$repo_dir" diff --cached --quiet; then
    printf '%s\n' 'release source must be packaged from a clean tracked checkout' >&2
    exit 1
fi

archive_name="syn-remote-source-${release_id}.tar.gz"
mkdir -p "$output_dir"
output_path="$output_dir/$archive_name"
if [ -e "$output_path" ] || [ -L "$output_path" ]; then
    printf 'refusing to replace existing release artifact: %s\n' "$output_path" >&2
    exit 1
fi

stage_dir=$(mktemp -d)
temporary_output="$output_dir/.${archive_name}.incomplete.$$"
trap 'rm -rf "$stage_dir"; rm -f "$temporary_output"' EXIT HUP INT TERM
bundle_root="$stage_dir/syn-remote-source-${release_id}"
mkdir -p "$bundle_root"
git -C "$repo_dir" archive "$release_commit" | tar -x -C "$bundle_root"
mkdir -p "$bundle_root/release" "$bundle_root/.cargo"
install -m 0644 "$release_json" "$bundle_root/release/release.json"

# Vendor from the exact archived source. The resulting bundle can build without
# granting the remote machine network access to Cargo registries.
(
    cd "$bundle_root"
    cargo vendor --locked --versioned-dirs vendor > .cargo/config.toml
)

source_date_epoch=$(git -C "$repo_dir" show -s --format=%ct "$release_commit")
tar --sort=name --format=posix --mtime="@$source_date_epoch" \
    --owner=0 --group=0 --numeric-owner \
    --pax-option=delete=atime,delete=ctime \
    -C "$stage_dir" -cf "$stage_dir/source.tar" "syn-remote-source-${release_id}"
gzip -n -c "$stage_dir/source.tar" > "$temporary_output"
# A hard link is an atomic create-only publication on this filesystem. It fails
# rather than replacing an artifact produced by another release process.
if ! ln "$temporary_output" "$output_path"; then
    printf 'refusing to replace existing release artifact: %s\n' "$output_path" >&2
    exit 1
fi
rm -f "$temporary_output"
printf '%s\n' "$output_path"
