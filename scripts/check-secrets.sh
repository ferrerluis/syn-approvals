#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
scanner=${GITLEAKS_BINARY:-gitleaks}
if [ "$("$scanner" version)" != 8.30.1 ]; then
    printf '%s\n' 'This audit requires Gitleaks 8.30.1.' >&2
    exit 1
fi
if [ "$(git -C "$repo_dir" rev-parse --is-shallow-repository)" != false ]; then
    printf '%s\n' 'Refusing a partial history scan; fetch full history first.' >&2
    exit 1
fi

# -m includes each side of merge commits. Reflogs/stashes are local-only but
# should also be checked before any cleanup or publication. Redact findings;
# never upload scan reports containing candidate credentials as CI artifacts.
"$scanner" git "$repo_dir" \
    --config "$repo_dir/.gitleaks.toml" \
    --log-opts='--all --reflog --full-history -m' \
    --ignore-gitleaks-allow --redact --no-banner

# Also check the proposed index, including newly added files not in history.
"$scanner" git "$repo_dir" \
    --config "$repo_dir/.gitleaks.toml" --pre-commit --staged \
    --ignore-gitleaks-allow --redact --no-banner
