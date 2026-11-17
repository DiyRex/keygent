# ADR 0002 — Composing with lean-ctx (and any other hook) via a chain composer

- **Status:** accepted
- **Date:** 2026-11-15
- **Verified against:** lean-ctx **3.11.0** (`/opt/homebrew/bin/lean-ctx`), Claude Code 2.1.325, on macOS. Spike notes are below.

## Observed behavior (spike, 2026-11-15, synthetic payloads, no secrets)

| Input `command` | `lean-ctx hook rewrite` output |
|---|---|
| `ls -la` | `permissionDecision: "allow"`, `updatedInput.command = "/opt/homebrew/bin/lean-ctx -c 'ls -la'"` |
| `keygent run -- ls -la` | allow, wrapped: `lean-ctx -c 'keygent run -- ls -la'` (**doesn't recognize keygent**) |
| `keygent run --grant g1 -- git status` | allow, wrapped the same way |
| `git status && npm test` | allow, wrapped |
| a command with nested quotes + placeholder | allow, **not wrapped** (passthrough on complex quoting) |

- lean-ctx registers `PreToolUse` (`Bash\|bash` → `lean-ctx hook rewrite`), and `UserPromptSubmit` / `PostToolUse` (`.*` →
  `lean-ctx hook observe`). Its observe hook **sees every prompt and tool output** and returns `additionalContext`.
- It returns **`allow` for every Bash command**. With Claude Code's precedence, keygent's `ask`/`deny` still win.
- Claude Code runs matching hooks **in parallel**, and how two `updatedInput` results combine is undocumented (ADR 0001 #3).

## Problems this creates

1. **Race on rewrite:** whether lean-ctx's or keygent's `updatedInput` wins is arbitrary. If lean-ctx wins, placeholders run unrewritten and
   manifest bindings don't apply. That fails safe (no secret), but the tool is broken.
2. **Observers see raw data first:** lean-ctx's `observe` receives a pasted secret, or an unredacted tool output (for example a `Read` of a file
   containing a value), **in parallel** with keygent's block or redaction. It could store that data in its archive or memory.

## Options

1. **Mutual idempotence:** requires changing lean-ctx, and doesn't solve problem 2. Rejected.
2. **Chain composer (chosen):** `keygent integrate lean-ctx` replaces lean-ctx's entries for those three events with
   `keygent hook <event> --chain '<original lean-ctx command>'`. keygent always runs first:
   - **prompt:** keygent blocks → lean-ctx is never called.
   - **pre:** keygent rewrites to `keygent run …`, then passes the rewritten payload to `lean-ctx hook rewrite`, which wraps it to
     `lean-ctx -c '… keygent run …'` (keygent innermost). The final decision is the most restrictive of the two.
   - **post:** keygent redacts, then passes the **redacted** payload to `lean-ctx hook observe`.

## Decision

Option 2, generalized as `keygent integrate chain <event> <cmd>` for any third-party hook. `doctor` warns about unchained observers
or rewriters on those events. Every change is backed up first, and `--remove` restores the original entries byte-for-byte.

## Consequences

- If lean-ctx updates and changes its hook command, `doctor` notices that the chained command differs from what lean-ctx installs, and offers to re-chain.
- Chaining adds one process spawn per event. That falls within the 30 ms (50 ms Windows) budget and is measured in Phase 5.
- lean-ctx's own redaction stays on as a third layer. Its allowlist gets `keygent`, and its secret paths get the vault and runtime dir.
