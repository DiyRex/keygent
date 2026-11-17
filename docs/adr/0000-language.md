# ADR 0000 — Implementation language: Rust

- **Status:** accepted
- **Date:** 2026-11-15
- **Verified against:** n/a (internal decision)

## Context

The spec requires a single static binary of at most 2 MB, an idle agent RSS of at most 5 MB, a hook p95 of at most 30 ms, and key material held
in `mlock`ed memory that is reliably zeroized. Both Rust and Go were considered. Go is already installed on the
dev machine. Rust is not yet installed.

## Options

1. **Go**
   - Pros: fast builds, trivial cross-compilation, solid `x/crypto` (chacha20poly1305, argon2), and a good stdlib for
     sockets, JSON and exec.
   - Cons: the runtime alone takes ~1.5 MB of the binary. With crypto and JSON a stripped binary is typically 3–5 MB,
     over budget. The GC can move and copy heap data, so zeroizing a `[]byte` does not guarantee that no other copies exist.
     Allocating key memory with `mlock` means working outside the Go heap via syscalls and cgo-like tricks. Runtime overhead
     puts idle RSS near the 5 MB ceiling.
2. **Rust**
   - Pros: deterministic `Drop`, so `zeroize` works reliably, and keys can be allocated in one known, `mlock`ed buffer.
     With `opt-level="z"` and LTO, binaries of about 1 MB are realistic. No runtime, so idle RSS stays low. The audited
     RustCrypto crates the spec names are available. `prctl`, `SO_PEERCRED` and `getpeereid` are easy to reach.
   - Cons: slower builds and a steeper learning curve. A toolchain install is needed (`rustup`).

## Decision

**Rust (stable, edition 2024).** The size, memory-hygiene and RSS budgets are hard requirements, and Go cannot
meet them comfortably. The spec is also written around the Rust crates.

## Consequences

- Install the toolchain: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (or `brew install rustup`
  then `rustup-init`). `rust-toolchain.toml` pins `stable` with clippy and rustfmt.
- CI uses `dtolnay/rust-toolchain`. Size budget enforced by `scripts/size-check.sh`.
