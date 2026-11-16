#!/bin/sh
# keygent installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/DiyRex/keygent/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/DiyRex/keygent/main/install.sh | sh -s -- --version v0.1.0
#
# What it does (no sudo, no shell-rc edits, nothing outside the install dir and a temp dir):
#   1. downloads the release archive, SHA256SUMS and SHA256SUMS.sigstore.json
#   2. verifies the Sigstore signature of SHA256SUMS (keyless, pinned to this repo's release workflow)
#      using your cosign, or a pinned cosign it downloads into the temp dir and checks by SHA-256 first
#   3. verifies the archive's SHA-256 against the signed SHA256SUMS
#   4. refuses downgrades unless --allow-downgrade, then installs keygent to ~/.local/bin (or --prefix)
#
# Options: --version <vX.Y.Z>  --prefix <dir>  --allow-downgrade  --insecure-skip-signature (checksum only; not recommended)
set -eu

REPO="DiyRex/keygent"
PREFIX="${HOME}/.local/bin"
VERSION=""
ALLOW_DOWNGRADE=0
SKIP_SIG=0

COSIGN_VERSION="v3.1.4"
IDENTITY_RE='^https://github\.com/DiyRex/keygent/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$'
OIDC_ISSUER="https://token.actions.githubusercontent.com"

say()  { printf 'keygent-install: %s\n' "$*" >&2; }
fail() { say "error: $*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --prefix) PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
    --insecure-skip-signature) SKIP_SIG=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] && fail "don't run this as root — keygent installs per user"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar  >/dev/null 2>&1 || fail "tar is required"

# ── platform → release target ────────────────────────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$os/$arch" in
  Darwin/arm64)               TARGET="aarch64-apple-darwin";       COSIGN_ASSET="cosign-darwin-arm64"; COSIGN_SHA="9f9b8cd557cf2e5b3df3373a00baa005a86b02391e3e06dd0ce37b3a1533d3a4" ;;
  Darwin/x86_64)              TARGET="x86_64-apple-darwin";        COSIGN_ASSET="cosign-darwin-amd64"; COSIGN_SHA="9d1e4abe2b6be279ed0d2ff706fde1ccd738747c834e3e6d44039c238867334f" ;;
  Linux/x86_64|Linux/amd64)   TARGET="x86_64-unknown-linux-musl";  COSIGN_ASSET="cosign-linux-amd64";  COSIGN_SHA="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa" ;;
  Linux/aarch64|Linux/arm64)  TARGET="aarch64-unknown-linux-musl"; COSIGN_ASSET="cosign-linux-arm64";  COSIGN_SHA="ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2" ;;
  *) fail "unsupported platform $os/$arch (supported: macOS arm64/x86_64, Linux x86_64/arm64)" ;;
esac

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ── resolve version ──────────────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
  url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" \
    || fail "could not reach GitHub releases"
  VERSION="${url##*/}"
fi
printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail "no release found (got '$VERSION')"

# ── downgrade check ──────────────────────────────────────────────────────────
semver_num() { printf '%s' "$1" | sed 's/^v//' | awk -F. '{ printf "%d%06d%06d", $1, $2, $3 }'; }
DEST="$PREFIX/keygent"
if [ -x "$DEST" ]; then
  current="$("$DEST" version 2>/dev/null | grep -Eo 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  if [ -n "$current" ]; then
    if [ "$(semver_num "$VERSION")" -lt "$(semver_num "$current")" ] && [ "$ALLOW_DOWNGRADE" -ne 1 ]; then
      fail "installed $current is newer than $VERSION — pass --allow-downgrade to continue"
    fi
  fi
fi

# ── download ─────────────────────────────────────────────────────────────────
TMP="$(mktemp -d 2>/dev/null || mktemp -d -t keygent)"
trap 'rm -rf "$TMP"' EXIT INT TERM
NAME="keygent-$VERSION-$TARGET"
BASE="https://github.com/$REPO/releases/download/$VERSION"
say "downloading keygent $VERSION for $TARGET"
for f in "$NAME.tar.gz" SHA256SUMS SHA256SUMS.sigstore.json; do
  curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/$f" "$BASE/$f" || fail "download failed: $f"
done

# ── signature ────────────────────────────────────────────────────────────────
if [ "$SKIP_SIG" -eq 1 ]; then
  say "WARNING: --insecure-skip-signature — only the checksum will be checked, the file's origin is NOT verified"
else
  COSIGN="$(command -v cosign 2>/dev/null || true)"
  if [ -z "$COSIGN" ]; then
    say "cosign not found — fetching pinned cosign $COSIGN_VERSION into a temp dir"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/cosign" \
      "https://github.com/sigstore/cosign/releases/download/$COSIGN_VERSION/$COSIGN_ASSET" || fail "could not download cosign"
    [ "$(sha256 "$TMP/cosign")" = "$COSIGN_SHA" ] || fail "cosign checksum mismatch — refusing to continue"
    chmod 0755 "$TMP/cosign"
    COSIGN="$TMP/cosign"
  fi
  say "verifying signature (Sigstore, release workflow of $REPO)"
  "$COSIGN" verify-blob "$TMP/SHA256SUMS" \
      --bundle "$TMP/SHA256SUMS.sigstore.json" \
      --certificate-identity-regexp "$IDENTITY_RE" \
      --certificate-oidc-issuer "$OIDC_ISSUER" \
      --certificate-github-workflow-repository "$REPO" >/dev/null 2>&1 \
    || fail "signature verification FAILED — do not install this file"
fi

# ── checksum ─────────────────────────────────────────────────────────────────
expected="$(awk -v n="$NAME.tar.gz" '$2 == n || $2 == "*"n { print $1 }' "$TMP/SHA256SUMS")"
[ -n "$expected" ] || fail "$NAME.tar.gz is not listed in SHA256SUMS"
[ "$(sha256 "$TMP/$NAME.tar.gz")" = "$expected" ] || fail "checksum mismatch — do not install this file"
say "signature and checksum OK"

# ── install ──────────────────────────────────────────────────────────────────
tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
[ -f "$TMP/$NAME/keygent" ] || fail "archive layout unexpected"
mkdir -p "$PREFIX"
cp "$TMP/$NAME/keygent" "$TMP/keygent.new"
chmod 0755 "$TMP/keygent.new"
mv -f "$TMP/keygent.new" "$DEST"
say "installed $DEST ($VERSION)"

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) say "note: $PREFIX is not on your PATH. Add it in your shell profile, e.g.: export PATH=\"$PREFIX:\$PATH\"" ;;
esac
say "next: keygent init   (if a broker is already running after an upgrade: keygent seal && keygent unseal)"
