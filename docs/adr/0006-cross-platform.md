# ADR 0006 — Cross-platform from v1 (Linux, macOS, Windows)

- **Status:** accepted
- **Date:** 2026-11-15
- **Verified against:** design review. Every primitive listed in [PLATFORMS.md](../PLATFORMS.md) must be confirmed in the Phase 0
  platform spike on real machines (including how Claude Code runs Bash and hooks on Windows).

## Context

The owner wants keygent to be safe to run on macOS, Windows and Linux. SPEC v2 deferred Windows to Phase 6, and it assumed
Unix-only primitives (`mlockall`, `fork`, Unix sockets, `SO_PEERCRED`, POSIX `sh`, process groups). Several v2 mechanisms
also turned out to be weaker than claimed on some OS (no `mlockall` on macOS; process groups can be escaped by double-fork; path
deny rules can be bypassed by case, symlinks, 8.3 names or alternate data streams).

## Decision

1. **All three OSes are first-class from Phase 1.** A phase is done only when its tests pass on Linux, macOS and Windows.
2. **One `Platform` trait** (`src/platform/`) with an implementation per OS that uses that OS's strongest native mechanism (see
   PLATFORMS.md). This is the only place for `unsafe`/FFI: `libc` on Unix, `windows-sys` on Windows.
3. **Uniform designs that work everywhere** were chosen over per-OS tricks:
   - The broker is started by **spawn + exec with an inherited pipe** (no `fork` without `exec`), and the DEK is handed over that pipe.
   - **Locked arena for secret material + zero-on-free global allocator** in the broker on every OS. `mlockall` adds
     a layer on Linux. Swap exposure of the remaining heap on macOS and Windows is documented (SPEC §5.4).
   - **Endpoint at a fixed per-user location** taken from the OS, never from env vars (SPEC §5.4).
   - Children get **default process state**: broker mitigation policies are applied at runtime and not inherited, and `NO_NEW_PRIVS` is not used.
   - **Mutual challenge-response** between the CLI and the broker, so a squatting fake broker never receives a passphrase or a value.
   - **Contained children:** Job Object (Windows), subreaper + process group (Linux), process group + run-id env-tag sweep
     (macOS, **best effort**: a child that unsets the tag and reparents to launchd can escape).
   - **Canonicalize, then match** for every path rule (case-folding where the filesystem is case-insensitive).
4. **Shell dialects:** POSIX `sh`/`bash` (Linux, macOS, Git Bash on Windows) and PowerShell 7. `cmd.exe` is **not**
   supported for placeholders, because its quoting cannot be made safe. Placeholders are rewritten per dialect (`"${KEYGENT_X}"` / `$env:KEYGENT_X`) in non-argv positions only; argv use is refused by default (SPEC §3.2.6).
5. **Device safety rules** (SPEC §3.3): no admin/root, per-user only, no services or drivers, no shell-rc edits, loopback-only
   listener, no telemetry, clean `uninstall`.
6. **Signed releases on every OS before GA:** cosign + provenance everywhere, plus macOS Developer ID and notarization (which also
   enables the hardened runtime that blocks `task_for_pid` and `DYLD_*` injection), and Windows Authenticode.

## Consequences

- More platform code and a 3-OS test matrix. The release check job runs on all three.
- The hook latency budget is **50 ms on Windows** (process creation and Defender scanning), 30 ms elsewhere.
- Windows-specific **T2** gap (SPEC §2.1): same-user processes can read a child's environment through `ReadProcessMemory` on the PEB. This is the same class
  of gap as `/proc/<pid>/environ`, and the egress proxy is the fix.
- The macOS hardened runtime needs a paid Apple Developer ID. Without it, broker memory protection on macOS rests on PT_DENY_ATTACH
  only, and `doctor` reports that.
