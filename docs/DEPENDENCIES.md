# Dependencies

Every crate needs a justification: **size delta** (measured on a `--release` linux-x86_64 build) and **why std
is not enough**. Budget: total binary ≤ 2 MB (target 1.5 MB).

| Crate | Version | Size Δ | Why std is not enough | Added in |
|---|---|---|---|---|
| `chacha20poly1305` | 0.11 | crypto set +65 KB (musl, spike 03) | AEAD; mandated (SPEC §4) | Phase 1 |
| `argon2` | 0.6 (`alloc`, `zeroize`) | in crypto set | Argon2id KDF; mandated | Phase 1 |
| `hkdf` / `hmac` / `sha2` | 0.13 / 0.13 / 0.11 | in crypto set | key separation, header MAC; mandated | Phase 1 |
| `zeroize` / `getrandom` | 1.9 / 0.4 | in crypto set | memory hygiene, OS RNG; mandated | Phase 1 |
| `libc` | 0.2 (unix only) | ~2 KB | termios, poll, statfs, getpwuid_r, fcntl; std has no API for these | Phase 1 |
| `rustls` | 0.23 (`ring`, `std`, `tls12`) | release per target with custody wired (2026-11-28): aarch64-darwin 1,497,392 · x86_64-darwin 1,756,768 · aarch64-musl 1,742,008 · **x86_64-musl 2,051,560** (45,592 under the hard cap) · armv7 1,583,600 · riscv64 1,593,048 | TLS client for the custody proxy: the broker dials the real API itself (ADR 0022); std has no TLS. Roots come from the **OS CA bundle** at fixed paths (an embedded `webpki-roots` list cost +57,792 B on x86_64-musl and was dropped). TLS 1.3-only would save another 40,792 B (owner decision). `ring` needs a C compiler for musl (zig in releases, `musl-tools` in the Linux container) | Custody C1 |
| ~~`objc2` + `objc2-foundation`~~ | removed in Phase 2 | — | `objc2` always links Foundation (+AppKit for the pasteboard): every keygent process idled at 8.7 MB RSS (plain Rust: 1.4 MB). Replaced by `dlopen`/`dlsym` of libobjc + AppKit inside `reveal --copy` only (raw `objc_msgSend` fallback named above) | Phase 1 → removed Phase 2 |

**Phase 1 release sizes:** aarch64-apple-darwin 586 096 B · x86_64-unknown-linux-musl 822 904 B · aarch64-unknown-linux-musl 724 128 B
(budget 2 MB, target 1.5 MB). Windows not built (ADR 0010).

## Candidates measured (Phase 0)

Measured 2026-11-16 on `x86_64-unknown-linux-musl`, release profile, each crate alone vs the std-only baseline.
Raw data and method: [spikes/03-dep-sizes.md](spikes/03-dep-sizes.md). "Proposal" is for review; nothing is added to `Cargo.toml` yet.

| Purpose | Candidate (version) | Size Δ | Proposal |
|---|---|---:|---|
| AEAD | `chacha20poly1305` 0.11.0 | 25.5 KB | mandated, accept |
| KDF | `argon2` 0.6.0 (`alloc`, no `password-hash`) | 23.7 KB | mandated, accept |
| HKDF / HMAC / SHA-256 | `hkdf` 0.13.0, `hmac` 0.13.0, `sha2` 0.11.1 | 14.4 / 13.1 / 12.5 KB (sha2 shared) | mandated, accept |
| Memory hygiene / RNG | `zeroize` 1.9.1, `getrandom` 0.4.3 | 0.4 / 1.2 KB | mandated, accept |
| Crypto set combined (without p256) | all of the above | **65.1 KB** | |
| WebAuthn verify | `p256` 0.14.0 (`ecdsa`, verify only) | 48.3 KB | accept in Phase 4 (only the console needs it) |
| Multi-pattern match | `aho-corasick` 1.1.5 | 206 KB (186 KB without `perf-literal`) | **hand-roll** (~10 % of the hard budget). Fall back to the crate only if the Phase 2 benchmark misses 200 MB/s |
| JSON (hook I/O) | `serde_json` 1.0.154 + serde derive / `miniserde` 0.1.46 / `tinyjson` 2.5.1 | 43.6 / 31.2 / 73.6 KB | **hand-roll** a total, capped parser (hook JSON is a hand-written, fuzzed parser). `serde_json` is the fallback |
| TOML (manifest) | `toml` 1.2.1 / `basic-toml` 0.1.10 (+ serde) | 150.8 / 108.3 KB | **hand-roll the subset** FORMATS needs. Both crates are too large |
| CLI parsing | `lexopt` 0.3.2 | 10.8 KB | hand-roll (fixed command set). `lexopt` is acceptable if the parser grows |
| Unix FFI | `libc` 0.2.191 | ~2 KB (scales with calls) | accept |
| Windows FFI | `windows-sys` 0.61.2 | **not measured** (needs a Windows host) | expected ≈ `libc`; measure in the Windows spike with the real call set (named pipes, DACLs, VirtualLock, Job Objects, mitigations, console, DPAPI, Credential Manager, clipboard, toast). The full WinRT `windows` crate stays out; Windows Hello via minimal hand-written COM or NCrypt, per the spike |
| macOS LocalAuthentication | `objc2` 0.6.5 + `objc2-foundation` 0.3.2 + `objc2-local-authentication` 0.3.2 | ≤ 17.5 KB (Mach-O, page-quantized) | accept, macOS-only target dep |
| Passphrase wordlist + common passwords | EFF large list (~60 KB) + top-10k (~80 KB), embedded | 143.6 KB (= data size) | accept |
| Linux Secret Service, clipboard, notifications | spawn `secret-tool` / `wl-copy` / `notify-send` at fixed paths | 0 | as planned, no crate |
| SBOM | `cargo-cyclonedx` (release CI only) | 0 (not linked) | as planned |
| Audit segment compression | `miniz_oxide` 0.8 (DEFLATE, `with-alloc`) | **33.3 KB** (aarch64-darwin, 2026-11-28) | proposed for audit v2 ([ADR 0018](adr/0018-audit-log-v2.md)); std has no compressor. 3.6× on a 20k-record sample |
| Policy engine | `cedar-policy` 4.x (`default-features = false`) | **1,582,816 B alone** (88 crates, aarch64-darwin, 2026-11-28) | **rejected** (over the 2 MB cap with keygent; owner decision: skip, [ADR 0020](adr/0020-cedar-policy.md)) |

**Projected binary (Linux musl):** baseline 372 KB + crypto 101 KB + wordlists 144 KB + libc ≈ **620 KB** before product code.

## Baseline

| Build | Size |
|---|---|
| empty `main`, aarch64-apple-darwin | 285 904 B |
| std-only spike baseline (args + stdout), x86_64-unknown-linux-musl | 372 248 B |
| std-only spike baseline, aarch64-apple-darwin | 286 032 B |

**Phase 2 RSS (broker idle, 20 secrets):** macOS arm64 2.86 MiB · Linux aarch64 static musl 2.32 MiB (200 secrets: 2.53 MiB) ·
Linux glibc dev build 5.23 MiB (not shipped; `mlockall` pins glibc's larger mappings). Budget 5 MB.
