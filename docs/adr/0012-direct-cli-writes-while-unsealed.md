# ADR 0012 — The CLI writes the vault directly while unsealed; the broker reloads

- **Status:** proposed (Phase 2 review)
- **Date:** 2026-11-16
- **Verified against:** keygent Phase 1/2 code; SPEC v6 §5.2 "Who writes", ADR 0004 request table

## Context

SPEC §5.2 says: while unsealed, every mutation goes through the broker (`AddValue`, `Rotate`, `Remove`, `Rename`, `EditPolicy`, `Trust`,
`Rekey`, … as authenticated frames). Every one of those commands already requires the passphrase in the human's terminal, and the CLI that
holds the passphrase can derive the DEK itself. Routing them through the broker would duplicate each Phase 1 command as a protocol
request without adding an authentication factor.

## Options

1. **All mutations via authenticated broker frames (SPEC as written).** Pros: one writer while unsealed. Cons: ~12 new request types and
   value-carrying `Sealed` frames (more protocol surface, more fuzzing); no extra factor, since the passphrase is the gate either way.
2. **CLI writes directly under the vault lock; the broker reloads.** Every write already holds `vault.kgt.lock`, bumps `generation`
   and re-MACs the header. Before using the index, the broker checks the file's generation; on change it re-reads under the lock and
   re-verifies the header MAC with its own `K_hdr` (a different DEK or tampering → **seal**, as SPEC §5.2 "Integrity on reload" already says).
   The broker's own writes (`capture`, exposure marks, audit anchor) take the same lock.

## Decision (proposed)

Option 2. The protocol keeps only what lives in broker memory or is agent-initiated: `Status`, `List`, `Seal`, `Check`, `GrantCreate`,
`AwaitGrant`, `Pending`, `Approve` (+`Auth`), `Deny`, `Run`, `Capture`, `Redact`, `MatchPrompt`, `MarkExposed`. `Reveal` is served by the
CLI locally (it has the passphrase), so **no broker response ever carries plaintext**, which is stricter than ADR 0004.

## Threat check

- **T2 agent writes the vault file directly:** it can't produce a valid header MAC without the DEK → the broker seals on reload (DoS only,
  same as deleting the file).
- **T2 agent races a CLI write:** both sides take `vault.kgt.lock`; the broker re-reads only under the lock.
- **Stale broker state after `rm`/`rotate`:** reload happens before every request that reads the index or values; the redactor keeps old
  values until seal (SPEC §5.7.5), so a rotate never weakens redaction.
- **Factor changes (`passwd`/`rekey`/`recover`)** must still seal the broker first (SPEC §5.2): the CLI sends `Seal` (no auth needed) and
  waits until the endpoint is gone before writing. A rekeyed vault would fail the broker's MAC check anyway (fail closed).
- **Fails open?** No path: any reload error seals.

## Consequences

- SPEC §5.2 "Who writes" and the ADR 0004 request table need updating on acceptance (SPEC §17 row).
- Audit records for human mutations are written by the CLI (it can derive `K_audit`), appended under the audit lock.
