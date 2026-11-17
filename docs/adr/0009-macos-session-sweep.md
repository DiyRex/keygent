# ADR 0009 — macOS run containment: session-id sweep plus env tag

- **Status:** proposed
- **Date:** 2026-11-16
- **Verified against:** macOS 26.6.2 arm64 (SIP on), Linux 7.0.12 container; [spike 04](../spikes/04-platform-unix.md) §2, §4

## Context

SPEC §5.4, ADR 0006 and PLATFORMS contain macOS children with "process group + `KEYGENT_RUN_ID` env tag, `KERN_PROCARGS2` sweep at run end
(best effort)". The spike shows that on macOS 26, `KERN_PROCARGS2` returns argv but **no environment** for Apple platform binaries
(`/bin/sleep`, `/bin/sh`, `/usr/bin/curl`) when read by another same-user process. A child that runs `(sleep 30 &)` or `curl … &` therefore
leaves a survivor the env-tag sweep can't see. That isn't an adaptive attack, just ordinary shell use (T1/T2).

A session-id sweep (`setsid()` in the child before exec, then kill every pid where `getsid(pid) == run_sid`) found every `&` and `nohup`
survivor, Apple binaries included, in < 0.5 ms. Escaping it takes a deliberate `setsid()`.

## Options

1. **Keep the env-tag sweep only.** Pros: no change. Cons: misses common survivors on current macOS. The SPEC claim is weaker than it reads.
2. **Session-id sweep only.** Pros: fast, sees platform binaries. Cons: a single `setsid()` escapes.
3. **Union: session id + env tag + process group.** Pros: an escape needs `setsid()` **and** either a platform binary or unsetting the tag.
   Cons: slightly more code. `setsid()` detaches the child from a controlling terminal, which doesn't matter because runs are pipes-only (SPEC §2.1).

## Decision (proposed)

Option 3 on macOS. Every run's child calls `setsid()` in pre-exec (that also makes it a process-group leader, so signals still go to the
pgid). At run end and in the crash sweep, kill the union of {pids with `getsid == run_sid`} and {pids whose `KERN_PROCARGS2` env carries the
`KEYGENT_RUN_ID`}. Linux keeps the subreaper + pgid and may add the same session check cheaply. It stays **best effort** on macOS (T3 escape).

## Consequences

- SPEC §5.4 (crash recovery), ADR 0006 §3, PLATFORMS "Child containment" and THREATS row "Child double-forks" need the wording change and a
  SPEC §17 row once accepted.
- The crash sweep after a broker restart must persist each live run's `run_sid` (the run dir already holds per-run state).
- Leak suite: add `(sleep N &)` and `nohup` survivor cases on macOS. Keep the `setsid` + `env -u` cases as documented known gaps.
- PID reuse: kill only pids whose session id **and** start time are recorded after the run started, to avoid hitting an unrelated process that
  reused a session id after the session leader exited.
