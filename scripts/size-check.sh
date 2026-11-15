#!/usr/bin/env sh
# Fail if the release binary exceeds the size budget. Usage: scripts/size-check.sh [path] [max_bytes]
set -eu
BIN="${1:-target/release/sealr}"
MAX="${2:-2097152}"     # 2 MiB hard limit
TARGET=1572864          # 1.5 MiB soft target

[ -f "$BIN" ] || { echo "size-check: $BIN not found; run cargo build --release" >&2; exit 2; }
SIZE=$(wc -c < "$BIN" | tr -d ' ')
echo "size-check: $BIN = $SIZE bytes (limit $MAX, target $TARGET)"
[ "$SIZE" -le "$MAX" ] || { echo "size-check: FAIL over budget" >&2; exit 1; }
[ "$SIZE" -le "$TARGET" ] || echo "size-check: WARN over 1.5 MiB target" >&2
