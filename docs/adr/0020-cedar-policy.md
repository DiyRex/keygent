# ADR 0020 — Cedar for the policy layer: measured cost and options

- **Status:** rejected — owner decision 2026-11-28: skip `cedar-policy` entirely (not worth it for keygent)
- **Date:** 2026-11-28
- **Verified against:**
  - `cedar-policy` 4.x (crates.io, resolved 2026-11-28), with `default-features = false`.
  - Built with keygent's release profile (`opt-level = "z"`, fat LTO, `codegen-units = 1`, `panic = "abort"`, strip) on
    rustc 1.100, aarch64-apple-darwin.

## Context

The owner asked to use Cedar (CNCF sandbox, `cedar-policy` crate) for the policy part. ADR 0016 had adopted Cedar-shaped
**export** only, without an engine, because of the binary budget.

The budget is ≤ 2 MB hard and ≤ 1.5 MB target (SPEC §4). keygent is currently 852–1,087 KB per target.

**Measurement.** A minimal program that parses a policy set and runs `Authorizer::is_authorized` once came to
**1,582,816 bytes** stripped, across 88 crates. Adding it to keygent gives about 2.4 MB, which is over the hard cap on every target.

## Options

1. **A — Embed `cedar-policy` as the broker's policy decision point.**
   - Pros: one standard policy language, with Cedar's analyzability (validation against a schema).
   - Cons: breaks the 2 MB cap. Needs a SPEC §4 change to about 3 MB and adds 88 crates to the trusted base of the only process
     that holds plaintext.
   - Allow rules (§6.2) need argv grammar and binary pins. Cedar would express those as entity attributes that keygent still
     computes, so keygent's matcher remains.
2. **B — Cedar as the policy language of record; keygent's native evaluator enforces it; `cedar-policy` only as a dev-dependency.**
   - `keygent policy export --format cedar` emits the exact policy as Cedar policies plus a Cedar schema:
     - principals: agents and humans;
     - actions: `run`, `capture`, `reveal`, …;
     - resources: handles and sets;
     - context: tool sha, argv shape, tier.
   - A **differential test** (dev-dependency, never in the release binary) feeds the same generated requests to Cedar's
     `Authorizer` and to keygent's evaluator. It fails on any disagreement.
   - Users get Cedar tooling (`cedar validate`, `cedar authorize`, policy review) with zero size or runtime cost.
3. **C — A Cedar subset parser in keygent** (import user-written Cedar).
   - That means writing a custom parser for a security language, which is error-prone. Rejected.
4. **D — An optional `keygent-cedar` helper binary** that the broker execs for decisions.
   - A second binary to pin and verify, a process spawn on every decision (latency budget), and the plaintext process trusting
     another binary's answers. Rejected.

## Decision

**Skip Cedar.** Option A breaks the size cap. Options B–D add work or a second trusted component with no T1/T2 gain for a
single-user tool whose policy is per-handle modes plus pinned allow rules. The owner decided not to use it in any form, so
there is no engine, no dev-dependency and no differential test. Policy review stays with `keygent ls`/`rule ls`, `edit` diffs
and `render_for_approval()`.

## Consequences

- No `cedar-policy` crate anywhere (release or dev). DEPENDENCIES keeps the measurement as the reason.
- ADR 0016's optional `policy export --format cedar` is dropped. JSON export stays possible if a reviewer needs one.
- Revisit only if keygent grows multi-user or org-wide policy (out of scope for v1).
