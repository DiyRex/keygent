#!/usr/bin/env sh
# Local quality gate. Run before publishing a release (CI only runs on release).
set -eu
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "fmt";    cargo fmt --check
step "clippy"; cargo clippy --locked --all-targets -- -D warnings
step "test";   cargo test --locked
step "build";  cargo build --locked --release
step "size";   sh scripts/size-check.sh

if command -v cargo-deny >/dev/null 2>&1; then
  step "deny"; cargo deny check
else
  echo "preflight: cargo-deny not installed (cargo install cargo-deny) — skipped" >&2
fi

printf '\npreflight: OK\n'
