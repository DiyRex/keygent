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

## Built: the `PreToolUse` chain (2026-11-29, Claude Code 2.1.332, lean-ctx 3.11.0)

Problem 1 is real, observed in a live `claude -p` run: both hooks fired in parallel and Claude Code ran lean-ctx's
`updatedInput` (a wrap of the **original** placeholder command), so keygent's rewrite was lost. Nothing leaked, since the
literal placeholder holds no value, but the command failed. What is built differs from the plan above in three ways:

- **Generic, inside `integrate claude`.** There's no separate `integrate lean-ctx`. Every `PreToolUse` group whose matcher
  names only Bash (`Bash`, `Bash|bash`, any case) and whose hooks are plain command hooks is moved into keygent's own
  entry as `--chain '{"at":<index>,"group":<the group as written>}'`. That covers lean-ctx and any other Bash rewriter.
  Groups with an `if` rule (only Claude Code can evaluate it), `async` hooks, or a broader matcher (`.*`) stay where they
  are, and `integrate` prints how many may still match Bash in parallel. Re-running `integrate` first restores the chained
  groups, so it's idempotent. `--remove` puts each one back at its original index, and the file round-trips exactly.
- **Order and combining** (`keygent hook pre --chain …`):
  - keygent's step runs first, and a keygent `deny` ends the chain;
  - each chained hook then gets the payload with `tool_input` already rewritten. Exec form is used if it has `args`,
    otherwise `sh -c`. Its `timeout` is honoured (default 60 s) and its process group is killed when it expires;
  - exit 2 blocks the call, passing on that hook's stderr. Any other failure is skipped unless that hook set
    `onFailure: block`;
  - decisions combine deny > ask > allow, and `additionalContext` strings are joined.
- **A chained hook may wrap keygent's command but not drop it.** Its `updatedInput` is used only if the command still
  contains `run --grant <id>`. That part is unquoted and unique per grant, so a wrapper's re-quoting of the launcher path
  doesn't break it. Only Claude Code's documented common top-level fields pass through (`continue`, `stopReason`,
  `suppressOutput`, `systemMessage`). lean-ctx also emits `modifiedArgs` and `updated_input`, which carry a command, and
  these are dropped so they can't bring back a rewrite keygent refused.

Verified: lean-ctx 3.11.0 given `'/opt/homebrew/bin/keygent' run --grant <id>` returns `allow` with
`lean-ctx -c ''\''/opt/homebrew/bin/keygent'\'' run --grant <id>'` (keygent innermost, as planned). keygent's own entry
timeout is 10 s plus each chained hook's timeout (capped at 600 s).

This is not a security boundary (ADR 0003): a chained hook is the user's own configuration, and the agent is the same OS
user. Problem 2 (observers on prompts and tool output) is still open and lands with the Phase 3 `prompt`/`post` hooks.

**Live check (2026-11-29, Claude Code 2.1.332, `claude -p --model haiku`, test-profile root, settings produced by
`integrate claude` from a copy of the user's lean-ctx group, user settings excluded with `--setting-sources project,local`):**
one `PreToolUse:Bash` hook ran (80 ms) and returned lean-ctx's wrap of `keygent run --grant <id>`. The command ran under
custody, the model saw only the dummy, the canary appeared nowhere in the transcript, and the audit log shows `grant` → `run`.
