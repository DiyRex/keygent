#!/usr/bin/env sh
# Local quality gate. Run before publishing a release (CI only runs on release).
set -eu
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "plaintext boundary (SPEC §4.2)"
# hook/, adapter/, policy/, proto/ and ui/ must never name secret types.
if grep -rnwE 'Secret|Dek|Kek|Subkey' src/hook src/adapter src/policy src/proto src/ui 2>/dev/null \
     | grep -vE '^[^:]+:[0-9]+:\s*//'; then
  echo "preflight: secret type referenced outside the plaintext boundary" >&2; exit 1
fi
# unsafe only in src/platform/
if grep -rnE '\bunsafe\b|allow\(unsafe_code\)' src --include='*.rs' | grep -v '^src/platform/' \
     | grep -vE '^[^:]+:[0-9]+:\s*//'; then
  echo "preflight: unsafe outside src/platform/" >&2; exit 1
fi

step "fmt";    cargo fmt --check
step "clippy"; cargo clippy --locked --all-targets -- -D warnings
step "test";   cargo test --locked
step "build";  cargo build --locked --release
step "size";   sh scripts/size-check.sh
step "no test hooks in release"
if grep -q 'KEYGENT_TEST_ROOT' target/release/keygent; then
  echo "preflight: release binary contains the test-profile override" >&2; exit 1
fi

if command -v cargo-deny >/dev/null 2>&1; then
  step "deny"; cargo deny check
else
  echo "preflight: cargo-deny not installed (cargo install cargo-deny) — skipped" >&2
fi

printf '\npreflight: OK\n'
