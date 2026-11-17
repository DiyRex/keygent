# ADR 0015 — Phase 2 M4: audit chain, allow rules, manifest trust, capture

- **Status:** proposed
- **Date:** 2026-11-16
- **Verified against:** keygent `phase-2-broker` (commits a86e464, 3ff2a42, da804e3, 773a6c2); macOS 26 and Linux
  `rust:1-bookworm` container, 111 unit + 27 end-to-end tests on both

## Context

M4 implements SPEC §9 (audit), §6.2 (allow rules), §5.6 (manifest trust) and §5.9 (capture). This ADR records what was
built where the spec leaves room, and the gaps that are still open.

## Decisions

1. **Audit chain (FORMATS §5).**
   - Records are hand-written JSONL with `mac` last. The MAC input is `enc(prev_mac) ‖ enc(line without the mac member)`,
     and the first record chains from zero bytes.
   - `mac` and `grant_key` are **hex**, not base64 (simpler, same strength). FORMATS has been updated.
   - Writers (the broker and the CLI) take a file lock on the log for read-tail + append + anchor.
   - **Fail closed:**
     - the broker refuses to start without a writable log;
     - a run needs its `start` record before exec, and the `end` record carries exit, redaction count and duration;
     - CLI value and policy changes append and anchor in the index **before** committing (no record, no change);
     - `reveal` is audited before the value is shown.
   - `audit --verify` goes through the broker, which holds `K_audit`. It checks the chain, the anchor file's last entry,
     and that the log reaches the index anchor (catches truncation).
   - **Not built yet:** rotation (10 MB × 5), the 10-min tripwire anchor, the `rekey` epoch record. Until the epoch
     record lands, `verify` fails after a `rekey` (that's the safe failure).
2. **Allow-rule grammar (§6.2).**
   - Positional pattern (literals, `*` = one non-dash argument). Anything after the pattern must be an allowlisted flag:
     `--f`, `--f v` with a non-dash `v`, or `--f=v` for value flags.
   - A trailing `**` must be followed by a non-empty flag list (CLI: `rule add h -- prog args… ** --flag --value-flag=`).
     This is the reading of the spec example where `flags` are listed without `**`: without flags nothing extra matches;
     with flags, only those flags do.
   - Shells, interpreters and transfer tools can't take `*`/`**`.
   - Rules apply only to handles in `allow` mode, and the CLI says so when adding to another mode.
   - A matching rule pre-approves a **bound** grant that execs the pinned program with the tokenized argv, without a
     shell. Linux hashes and execs through the same fd (`/dev/fd/N`). macOS hashes, then execs by path: a same-user
     swap window, **T2 residual**.
   - A changed binary falls back to `approve` with a re-pin warning (old → new hash, size, mtime). Approving does
     **not** update the rule; the human re-adds it.
   - `home = "scratch"` sets an empty HOME and XDG dirs. The per-tool config-env table (e.g. `AWS_CONFIG_FILE`) is not
     built yet.
3. **Manifest (§5.6).**
   - A strict subset parser: unknown keys, escapes and reserved env names are errors, which name the line.
   - `$NAME` / `${NAME…}` references are now recorded by the tokenizer. A command referencing a manifest name needs:
     the manifest trusted with **exactly** this content (else exit 76), the handle present and not denied, and the
     argv rule as for placeholders.
   - The command keeps `$NAME`; the broker sets `NAME`.
   - Such runs always need approval (an allow rule doesn't apply to them, since `$` makes a command ineligible).
   - `trust` shows the full file every time. **There's no diff**, because the old content isn't stored; storing it in
     the index is the proposed follow-up.
   - The global manifest (`config/global.toml`) is not read yet.
4. **Broker-side vault writes.** These are needed for `untrust` (agent-safe) and `capture`, which an agent triggers
   without the passphrase. They're limited to capability-reducing or create-only changes.
   - The broker takes the vault lock with `try_lock` (busy → `RateLimited`) and reloads.
   - It appends the audit record first, then applies the change. A failure there reopens from disk; a failed commit seals.
   - This extends ADR 0012 (the CLI writes directly), which assumed only the CLI writes.
5. **Capture (§5.9).**
   - **Every capture needs the human's approval** (review fix, 2026-11-16). An unapproved capture loop could fill the
     vault (1 000 handles, or the 8 MiB redactor cap) and lock the human out of `add`/`rotate`. The alternative was a
     per-session quota. A capture onto an existing handle is refused before anyone is asked to approve.
   - The env name is always `KEYGENT_<HANDLE>` (the literal reading of §5.9, and it can't land on a meaningful name).
   - The mode is always `approve`, whatever `default_mode` says, and the origin is `capture`.
   - It's create-only: an existing handle gets `NeedsAuth` (exit 1). The same strength, size and redactor-cap rules as
     `add` apply.
   - The capture target is part of the grant key and shown in the approval.
   - **Addition to the spec:** stderr of a capture run is held (≤ 1 MiB) and released only after redaction with the
     session redactor **and the new value**. Otherwise a tool that echoes its token on stderr would leak it. Proposed
     for SPEC §5.9.
6. **New protocol codes.** `Audit` = 12 (exit 79) and `Failed` = 13 (a human-facing line, exit 1). `NotTrusted` (2)
   maps to exit 76. The client still checks the shape of every relayed line.

## Consequences

- SPEC §5.9 should mention the stderr hold. FORMATS §5 now says hex. ADR 0012 should reference item 4.
- Still open for M5: the leak harness and T1/T2 cases, the THREATS rows for the macOS exec window (item 2) and capture.

## Review fixes (2026-11-16)

- Redactor: generic-detector hold-back capped at 64 KiB (held run redacted as one match) — no unbounded memory/rescans.
- `Vault::commit`: success once the vault file is replaced; a later tripwire failure is non-fatal (self-heals).
- Broker fails closed when a guard thread (output pumps, client watcher, runtime limit, seal watchers) can't start;
  `seal()` always kills active runs; seals requested under the state lock are deferred so the seal is audited.
- Executables are hashed streaming (64 KiB steps), hash cache capped at 4 096 entries.
- Captured stdout/stderr are moved, never copied, out of their zeroizing buffers; `Redact` runs outside the state lock.
- Allow rules: `--flag=value` with a dash-leading value no longer matches.
