#!/usr/bin/env bash
# Fails CI when a Rust crate reads an env var that's neither documented in
# .env.example nor listed in scripts/env-var-drift-baseline.txt.
#
# `config.json`/`.env.example` sprawl across ~70 crates with no single
# source of truth for "what env vars actually exist" is a known gap (see
# CLAUDE.md). This doesn't fix that — it stops it from silently getting
# worse: a *new* undocumented var fails the build; the pile of existing
# ones is grandfathered in the baseline file so unrelated PRs don't break.
#
# Run from anywhere; paths are resolved relative to this script's location.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rust_root="$(cd "$script_dir/.." && pwd)"
repo_root="$(cd "$rust_root/.." && pwd)"

env_example="$repo_root/.env.example"
baseline="$script_dir/env-var-drift-baseline.txt"

if [[ ! -f "$env_example" ]]; then
    echo "check-env-var-drift: $env_example not found" >&2
    exit 1
fi

# Vars from the process environment itself, never app config — reading
# these is never a documentation gap.
os_vars_regex='^(HOME|HOSTNAME|PATH|USER|USERNAME|PWD|SHELL|LANG|TERM|TMPDIR)$'

used=$(grep -rhoE '(std::)?env::var(_os)?\("[A-Za-z0-9_]+"\)|env_(str|bool|num|csv)(::<[^>]+>)?\("[A-Za-z0-9_]+"\)' \
    "$rust_root"/crates/*/src/*.rs "$rust_root"/crates/*/src/**/*.rs "$rust_root"/crates/*/src/**/**/*.rs 2>/dev/null \
    | grep -oE '"[A-Za-z0-9_]+"' | tr -d '"' | sort -u \
    | grep -vE "$os_vars_regex" || true)

documented=$(grep -oE '^[A-Za-z0-9_]+=' "$env_example" | tr -d '=' | sort -u)
baselined=$(grep -vE '^\s*#|^\s*$' "$baseline" | sort -u)

undocumented=$(comm -23 <(echo "$used") <(echo "$documented"))
new_drift=$(comm -23 <(echo "$undocumented") <(echo "$baselined"))

if [[ -n "$new_drift" ]]; then
    echo "check-env-var-drift: found env var(s) read in Rust code but not in .env.example:" >&2
    echo "$new_drift" | sed 's/^/  - /' >&2
    echo >&2
    echo "Either document each one in .env.example, or if it's a deliberate" >&2
    echo "internal/test-only var, add it to $baseline instead." >&2
    exit 1
fi

echo "check-env-var-drift: no new undocumented env vars."
