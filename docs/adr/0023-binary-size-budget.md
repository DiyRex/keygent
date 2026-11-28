# ADR 0023 — Binary size budget: 3 MB hard, 2 MB target

- **Status:** accepted (owner decision, 2026-11-28)
- **Date:** 2026-11-28
- **Verified against:** release builds of `main` @ 87d484b. GoReleaser snapshot and cargo-zigbuild, per target: aarch64-darwin
  1,504,160 B, x86_64-musl 2,057,616 B (the largest).

## Context

SPEC §4 set the release binary at ≤ 2 MB per target, with a 1.5 MB target. Credential custody (ADR 0022) needs a TLS client in
the broker: `rustls` with `ring`, about +680 KB. After dropping the embedded root list (OS bundle instead), x86_64-musl sat
39 KB under the cap.

The next custody steps need more room:

- C2: per-run CA, P-256 signing and DER;
- C3–C5: SigV4, Huawei and SharedKey re-signing;
- the hook (S2);
- the console client parts.

## Options

1. **TLS 1.3 only.** Saves 40,792 B, once. Breaks APIs that still speak only TLS 1.2, and buys one step at most.
2. **Separate `keygent-egress` binary.** Keeps the core small, but adds a second process that holds plaintext, a second
   binary to pin and verify, and IPC between them. That is a larger trusted base than the bytes it saves.
3. **Raise the cap to 3 MB, target 2 MB.** A single process still holds plaintext, and all the measured headroom is kept.

## Decision

Option 3: **≤ 3 MB hard, ≤ 2 MB target per target**. These stay unchanged:

- RSS (≤ 5 MB idle);
- hook latency (p95 ≤ 30 ms);
- `run` overhead;
- redaction throughput;
- the std-first rule. Every crate still needs a measured DEPENDENCIES line.

`scripts/size-check.sh` enforces the new numbers. `release-check.sh` uses it for every release target.

## Consequences

- Keeping each binary small remains a review criterion; the extra MB is headroom for custody and the hook, not a licence to
  bloat. A PR that crosses the 2 MB target says why in its size section.
- Historical ADRs (0000, 0016, 0020) keep the 2 MB figure they were written against.
