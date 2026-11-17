# ADR 0013 — Linux: clients can't hash a non-dumpable broker's executable

- **Status:** proposed (Phase 2 review)
- **Date:** 2026-11-16
- **Verified against:** keygent Phase 2 M1 on Linux 7.0.12 (Docker, `rust:1-bookworm`) and macOS 26.6.2; spike 04 §2–§3

## Context

SPEC §5.4 requires every client to check that the peer PID's executable is the installed keygent binary (path + hash). The same section
requires the broker to be non-dumpable (`PR_SET_DUMPABLE=0`), which is what blocks same-user `ptrace` and `/proc/<pid>/mem` on Linux
(spike 04 §3). On Linux a non-dumpable process's `/proc/<pid>/exe` is unreadable to same-user processes without `CAP_SYS_PTRACE`
(observed: `readlink` fails with EACCES), so the two requirements conflict. macOS `proc_pidpath` works on a `PT_DENY_ATTACH` broker.

## Options

1. **Drop non-dumpable** so clients can read `/proc/<pid>/exe`. Rejected: exposes broker memory (keys, values) to any same-user process.
2. **Keep non-dumpable; on Linux accept an unreadable executable** while still requiring: same uid, the peer PID holds `broker.lock`,
   PID start time matches the lock record. Where `/proc/<pid>/exe` *is* readable, the path + hash check still applies.

## Decision (proposed)

Option 2. Analysis of what a same-user squatter gains on Linux:

- It can only bind while **no real broker runs** (exclusive bind under `broker.lock`), i.e. while the vault is sealed.
- Auth flows (`unseal`, `approve`) verify the broker's HMAC proof with locally derived keys → a squatter gets neither passphrase nor values.
- `run` against a squatter has no secrets to leak (they are not in the squatter).
- Hooks: a squatter answering "no match" to `MatchPrompt`/`Redact` must not be worse than sealed. **Requirement for Phase 3:** hooks
  always run the local generic detectors, whatever the broker answers, so a squatter degrades protection to exactly the sealed level.

## Consequences

- THREATS row "Fake broker receives hook traffic" gets a Linux note: binary-hash check unavailable; residual equals sealed behaviour.
- Phase 3 hook design must keep local generic detection unconditional (listed above).
- `doctor` reports which identity checks were possible.
