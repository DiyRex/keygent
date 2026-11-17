# ADR 0010 — Windows verification deferred until a Windows host is available

- **Status:** accepted (owner decision)
- **Date:** 2026-11-16
- **Verified against:** n/a (process decision)

## Context

SPEC §0 rule 1, §13 and ADR 0006 require every phase to pass tests on Linux, macOS **and** Windows. The only machine available right now is a Mac
(Apple silicon). The Windows Phase 0 spike items (PLATFORMS checklist) and the `windows-sys` size measurement can't be run.

## Decision

Development continues on macOS (native) and Linux (Docker now, a desktop VM later). Windows verification is **deferred, not dropped**:

- Windows code still goes behind the `Platform` trait and `cfg(windows)`. Until it can run, it is **compile-checked only**
  (`cargo check`/`clippy --target x86_64-pc-windows-msvc`) and marked untested.
- No phase is reported **DONE** while its Windows tests haven't run. Reports say "DONE on macOS + Linux, Windows pending".
- The Windows spike runs before any Windows-specific design is relied on, in particular the native approval prompt (SPEC §4.3), which
  stays "terminal + console only" until then.
- Option for later: a Windows 11 ARM VM in UTM on the Mac would satisfy this without separate hardware.

## Consequences

- Windows-specific design risk (named pipes, DACLs, Job Objects, Windows Hello) is found later, possibly after the Unix code it mirrors is done.
- The release workflow still tests on Windows, so nothing ships untested on Windows.
