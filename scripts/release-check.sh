#!/usr/bin/env sh
# Checks one built release binary (run by GoReleaser for every target): size budget, and no test-profile hooks (SPEC §11).
set -eu
BIN="$1"
sh "$(dirname "$0")/size-check.sh" "$BIN"
if grep -q 'KEYGENT_TEST_ROOT' "$BIN"; then
  echo "release-check: $BIN contains the test-profile override" >&2; exit 1
fi
