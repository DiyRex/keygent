# ADR 0017 — Release pipeline (GoReleaser) and updates through Homebrew

- **Status:** proposed
- **Date:** 2026-11-28
- **Verified against:**
  - GoReleaser 2.20.3 OSS (local), docs fetched 2026-11-28: Rust builder (page updated 2026-09-05),
    deprecations (2026-10-22), snapshots (2026-11-19), sign, checksum, release, Actions
  - zig 0.17.1 and cargo-zigbuild 0.24.1 (local)
  - Homebrew on macOS 26 arm64: test tap install, `brew test`, `brew style`
  - cargo-cyclonedx 0.5.10
  - actionlint (local)

## Context

- The owner wants a public Homebrew tap and an easy way to stay up to date.
- CI minutes must not be spent automatically. Checks and releases run only when the owner starts them.
- SPEC §12 already lists a Homebrew tap and pins the Sigstore identity to `release.yml` on a `vX.Y.Z` tag.
- `install.sh` / `install.ps1` expect these assets:
  - `keygent-<tag>-<target>.<ext>` holding `keygent-<tag>-<target>/keygent`
  - `SHA256SUMS`
  - `SHA256SUMS.sigstore.json`
- The previous `release.yml` ran on `release: published`. It used one native runner per target, including two Windows MSVC targets.

## Options

1. **Keep the hand-written matrix workflow.** It already works, but it is six runners per release, and the formula would be hand-maintained.
2. **GoReleaser `builder: rust` on one macOS runner, cross-building with zig, and a formula generated from the signed checksums.**
3. **GoReleaser `homebrew_casks`.** This is GoReleaser's replacement for `brews`, which was deprecated in v2.10 and hard-deprecated in v2.16.
   - Casks are quarantined on macOS. The documented workaround is an `xattr -dr com.apple.quarantine` hook that bypasses
     Gatekeeper, which is the wrong default for a security tool.
   - The docs don't cover casks on Linux.
4. **A self-update command in keygent.** This needs network code, a TLS stack and signature verification in the binary (size
   budget). It would also be a new supply-chain path inside the broker's own binary.

## Decision

Option 2.

**Build**
- `.goreleaser.yaml` builds `aarch64`/`x86_64` × `apple-darwin` and `unknown-linux-musl`, plus Linux `armv7` (musleabihf) and
  `riscv64gc` (musl), from one macOS runner. Static musl means one Linux build covers glibc distros, Alpine and WSL.
  - armv7 and riscv64 are build-verified only (2026-11-28: 1,005,651 / 1,023,497 bytes). They have no runtime test until an
    emulator or board run. The installer maps `armv7l`/`riscv64` to them; Homebrew on Linux supports only x86_64/arm64.
  - Also built during the survey but **not shipped**: `i686` and `powerpc64le` musl (they build; agents don't realistically
    run there), `s390x` (no prebuilt std), `x86_64-unknown-freebsd` (compile error in `src/platform`; needs a FreeBSD port).
  - Darwin builds natively. Linux builds through zig: keygent links no Apple framework, because AppKit and objc are `dlopen`ed.
- Every binary passes `scripts/release-check.sh` (the size budget, now 3 MB per ADR 0023, and no `KEYGENT_TEST_ROOT`, per SPEC §11).

**Release assets**
- Archives, `SHA256SUMS` and a CycloneDX SBOM (`cargo cyclonedx`, from `Cargo.lock`) are signed keylessly with cosign.
- The release also carries a GitHub build-provenance attestation.

**Workflow** (`.github/workflows/release.yml`)
- It is `workflow_dispatch` only, with two modes:
  - `snapshot` runs on any branch and uploads the artifacts to the run for 14 days. Nothing is published.
  - `release` publishes, and runs only from a semver tag whose commit is on `main` and matches `Cargo.toml`.

**Homebrew**
- `scripts/brew-formula.sh` renders `Formula/keygent.rb` from `SHA256SUMS`. A formula, not a cask, means there is no quarantine hack and Linux works.
- The workflow verifies the cosign bundle of `SHA256SUMS` before it renders the formula.
- The workflow pushes the formula to the public tap `DiyRex/homebrew-tap` with a fine-grained token (`HOMEBREW_TAP_TOKEN`,
  contents: write on that one repo).
- Prereleases (`-rc…`) never update the tap.

**Updates**
- Users update with `brew upgrade keygent`. For automatic updates they can use `brew autoupdate start --upgrade`
  (Homebrew/homebrew-autoupdate).
- **keygent never updates itself** and makes no network calls (option 4 rejected).
- The formula caveat tells users to restart the broker after an upgrade (`keygent seal && keygent unseal`, SPEC §12).
- Hooks keep calling the stable `$(brew --prefix)/bin/keygent` symlink, never the versioned Cellar path.

## Consequences

**Windows**
- Windows is dropped from the release targets for now.
- The phase-2 code doesn't compile there yet (`platform::ipc` is unix-only; found by the snapshot, 2026-11-28).
- The old matrix had MSVC targets. cargo-zigbuild only supports Linux and macOS targets.
- When the Windows platform layer lands, add `x86_64-pc-windows-gnu`, or a separate `windows-latest` job, and test it with a snapshot first.
- `install.ps1` has no release asset until then.

**Checks before a release**
- The 3-OS check matrix is now Linux + macOS (ADR 0010 already defers Windows verification).

**Deprecation**
- GoReleaser's deprecated `brews` isn't used, so a GoReleaser v3 won't break the tap.

**Owner setup** (one-time)
- Create the public repo `DiyRex/homebrew-tap`.
- Add the `HOMEBREW_TAP_TOKEN` secret to `DiyRex/keygent`.
- Enable tag protection for `v*` (SPEC §12).

**Re-check**
- The Rust builder targets and zig version, at every GoReleaser major version.
- The cosign identity check in `install.sh` after the first real release.
