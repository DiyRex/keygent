# ADR 0020 — Cedar for the policy layer: measured cost and options

- **Status:** proposed. **Owner decision needed** (option B recommended).
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

Recommend **B**. It gives Cedar as the standard, reviewable policy format, with tests proving that what keygent enforces is what the
Cedar export says, and it keeps the 2 MB and RSS budgets.

If the owner prefers **A**, SPEC §4 must raise the hard cap (≥ 3 MB) and THREATS must record the larger trusted base. That
choice needs an explicit owner yes and a §17 row.

## Consequences

- Phase 3 (ADR 0016 item list): `policy export --format cedar` plus a schema file, and the differential test with `cedar-policy` under
  `[dev-dependencies]`. `cargo deny` covers dev-dependencies too.
- DEPENDENCIES records the measurement above. Re-measure if `cedar-policy` adds a minimal "evaluator only" feature.
