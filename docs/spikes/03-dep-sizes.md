# Spike 03 — dependency sizes

- **Date:** 2026-11-16
- **Toolchain:** rustc 1.100.0 (stable), release profile from `Cargo.toml` (`opt-level="z"`, fat LTO, 1 CGU, `panic=abort`, strip)
- **Hosts:** macOS 26 arm64 (native) · Linux x86_64 musl, cross-built in Docker `rust:1-bookworm` (aarch64) and linked with `rust-lld`
- **Code:** throwaway spike crate (not published). Each cargo feature exercises one crate on runtime input (`argv[1]`, `black_box`), so LTO can't
  drop the code. `measure.sh` (macOS) and `measure-linux.sh` (container) build each feature alone and diff it against the baseline.

## Method notes

- **Mach-O file sizes are useless for small deltas:** segments are padded to 16 KiB pages on arm64, so `hkdf`/`hmac`/`sha` show
  64–80 B and the larger crates jump in whole pages. The **Linux musl numbers below are the reference** (file size and `size` text+data
  agree within ~40 B).
- Each delta is **one crate in isolation**. Shared code (e.g. `sha2` under `hkdf` and `hmac`) is counted once in the combined rows.
- The baseline already contains std's `fmt`, `io` and `env::args`, which the product will use anyway.
- `wordlist` is a 140 KiB stand-in blob (EFF large list ≈ 60 KB + top-10k common passwords ≈ 80 KB). Embedded data costs its byte size.

## Results — x86_64-unknown-linux-musl (reference)

| Feature | Crate(s) (resolved) | Δ bytes | Notes |
|---|---|---:|---|
| baseline | std only | 372 248 total | static musl, stripped |
| chacha | `chacha20poly1305 0.11.0` (XChaCha20-Poly1305, `alloc`) | 25 504 | |
| argon | `argon2 0.6.0` (`alloc`, no `password-hash`) | 23 744 | |
| hkdf | `hkdf 0.13.0` + `sha2 0.11.1` | 14 432 | |
| hmac | `hmac 0.13.0` + `sha2 0.11.1` | 13 120 | |
| sha | `sha2 0.11.1` | 12 480 | |
| p256 | `p256 0.14.0` (`ecdsa`, verify only) | 48 288 | largest crypto item |
| zeroize | `zeroize 1.9.1` | 416 | |
| rand | `getrandom 0.4.3` | 1 216 | |
| **crypto-set** | chacha + argon + hkdf + hmac + sha + zeroize + rand | **65 120** | everything except `p256` |
| **crypto-all** | crypto-set + `p256` | **101 120** | |
| aho | `aho-corasick 1.1.5` (`std`, `perf-literal`) | 205 984 | without `perf-literal`: 185 888 |
| serde-json | `serde 1.0.229` (derive) + `serde_json 1.0.154`, incl. `Value` | 43 616 | |
| miniserde | `miniserde 0.1.46`, incl. `Value` | 31 232 | |
| tinyjson | `tinyjson 2.5.1` | 73 600 | larger than serde_json |
| toml | `toml 1.2.1` (`parse`, `serde`) + serde | 150 816 | |
| basic-toml | `basic-toml 0.1.10` + serde | 108 320 | |
| lexopt | `lexopt 0.3.2` | 10 784 | |
| libc | `libc 0.2.191` (mlock, getuid, rlimits) | 1 952 | bindings: cost scales with calls |
| wordlist | 140 KiB embedded data | 143 616 | |

## Results — aarch64-apple-darwin (page-quantized, for orientation only)

baseline 286 032 · chacha +16 592 · argon +16 640 · p256 +33 296 · crypto-set +33 296 · crypto-all +50 032 · aho +100 144 ·
serde-json +33 344 · miniserde +33 328 · tinyjson +66 464 · toml +116 528 · basic-toml +83 264 · lexopt +16 592 · libc +192 ·
wordlist +148 608 · **objc (`objc2 0.6.5` + `objc2-foundation 0.3.2` + `objc2-local-authentication 0.3.2`, LAContext) +17 456**
(one or two pages; real code is a few KB: `objc2` is mostly generic/inline). hkdf/hmac/sha/zeroize/rand fit in existing padding.

## Not measured (needs a Windows host)

- `windows-sys` (raw bindings, feature-gated): bindings have no code of their own, so the cost is import-table entries per called function.
  Expected to be in the same range as `libc`. **Measure on Windows** with the real call set (pipes, DACLs, VirtualLock, Job Objects,
  console, DPAPI, CredMan, clipboard).

## Projected budget (Linux musl)

baseline 372 KB + crypto-all 101 KB + wordlists 144 KB + libc ~2 KB ≈ **620 KB** before product code. That leaves ~1.4 MB to the hard
limit and ~0.9 MB to the 1.5 MB target. Adding `aho-corasick` + `toml` + `serde_json` would cost another ~400 KB (≈ 1 MB total).
