# ADR 0001 — Claude Code hook contract

- **Status:** accepted. The hooks page was **read in full verbatim** on 2026-11-15 (second pass). The remaining *verify* items (the `if`
  filter pattern, per-tool `tool_response` schemas, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_GIT_BASH_PATH`) are confirmed with captured payloads in Phase 3.
- **Date:** 2026-11-15
- **Verified against:** Claude Code **2.1.325** (installed), docs fetched 2026-11-15: https://code.claude.com/docs/en/hooks,
  /permissions, /env-vars, /permission-modes. Parts of the hooks page were summarized rather than read verbatim; those findings are marked *verify*.

## Findings

| # | Question | Answer | Source |
|---|---|---|---|
| 1 | Common stdin fields | `session_id`, `prompt_id`, `transcript_path`, `cwd`, `permission_mode` (`default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`), `hook_event_name`, … PreToolUse adds `tool_name`, `tool_input`, `tool_use_id`. PostToolUse adds `tool_response` (*verify*). UserPromptSubmit adds `prompt` (*verify*) | hooks#common-input-fields |
| 2 | PreToolUse output | `hookSpecificOutput{hookEventName, permissionDecision: allow\|deny\|ask\|defer, permissionDecisionReason, updatedInput, additionalContext}`. **Verified:** `updatedInput` "Replaces the entire input object, so include unchanged fields alongside modified ones." Permission rules are evaluated "against the input your hook returns" | hooks#pretooluse-decision-control |
| 3 | Several matching hooks | **Verified:** "its matching hooks run in parallel". "precedence is `deny` > `defer` > ask > allow". All `additionalContext` values are delivered. **Combining several `updatedInput` results is not documented anywhere on the page** (read in full) → ADR 0002 chain composer | hooks#hook-handler-fields |
| 4 | Replacing PostToolUse output | **Verified:** `updatedToolOutput` "Replaces the tool's output … before it is sent to Claude. The value must match the tool's output shape". It works for any tool. "For built-in tools, a value that doesn't match the tool's output schema is **ignored and the original output is used**" (fail-open, hence golden schemas). MCP output isn't validated. "`updatedToolOutput` only changes what Claude sees" (the transcript may keep the original) | hooks#posttooluse-decision-control |
| 5 | Blocking a prompt | **Verified:** `{"decision":"block","reason":"…","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}`. Without suppression the block message ends with `Original prompt:` + text and is written to the transcript. With it: "changes only the block message. The submitted text can still appear in local files such as the session transcript and your prompt history." The blocked prompt is not sent to the model | hooks#what-a-blocked-prompt-leaves-behind |
| 6 | Exit codes | 0 = JSON applies. 2 = blocking error. Other = non-blocking, and the action proceeds. "Claude never sees stderr from a hook that exits 0." Hooks have no controlling TTY | hooks#exit-code-output |
| 7 | Timeout / failure | `timeout` in seconds. The default is 600 for command hooks (30 for UserPromptSubmit). **Verified:** `onFailure: "continue" \| "block"` (≥ 2.1.295, command/http hooks). "With `block`, a failure does what exit code 2 does on that event." Failures = can't start, exit ≠ 0/2, timeout, invalid output | hooks#block-the-action-when-a-hook-fails |
| 8 | Permission modes | "Deny rules block in every mode, including `bypassPermissions`." **Verified (auto):** "a PreToolUse hook's `ask` normally sends the tool call to the permission prompt". `bypassPermissions`/`dontAsk` + hook `ask`: **not documented** → `confirm` is treated as `approve` there | permissions, hooks#pretooluse-ask-decisions-in-auto-mode |
| 9 | Env markers | **`CLAUDECODE=1`** in Bash, PowerShell and hook subprocesses. `CLAUDE_PROJECT_DIR` for hooks. `CLAUDE_CODE_SESSION_ID` (*verify*) | env-vars |
| 10 | Windows | Shell-form hooks run in Git Bash, or PowerShell if Git Bash is absent. Exec form needs a real `.exe`. The PowerShell tool is named **`PowerShell`**, so use matcher `Bash\|PowerShell`. `CLAUDE_CODE_GIT_BASH_PATH` (*verify*) | hooks |
| 11 | `permissions.deny` paths | gitignore syntax. `//abs/path` = absolute, `~/p` = home-relative, `./p` = cwd-relative. A Read deny also blocks Edit/Write and (best effort) Grep/Glob. Use `Read(...)`, not `Grep(...)` | permissions |
| 12 | Matchers | Letters, digits and `\|` mean exact names. Anything else is an unanchored JS regex. MCP tools are named `mcp__<server>__<tool>` | hooks |

## Decision

- **Hook entries:** exec form, the stable launcher path, `timeout: 5`. `onFailure: block` for UserPromptSubmit and placeholder Bash/PowerShell
  commands; `continue` elsewhere (SPEC §5.10.1). The broker enforces policy, and the static `permissions.deny` rules are the fail-safe (they hold in every mode).
- **PostToolUse:** build `updatedToolOutput` to each tool's exact schema (golden tests per Claude Code version). For an unknown tool, block + mark exposed.
- **Read deny** includes Claude Code's own transcripts and prompt history, which can hold raw prompts and tool outputs.
- **Matchers:** `UserPromptSubmit`; `PreToolUse` with `Bash|PowerShell`, `Write|Edit|MultiEdit|NotebookEdit`, `Read|Grep|Glob`; `PostToolUse` with `*`.
- **Prompt block** uses `decision: block` + `suppressOriginalPrompt: true`. It keeps the secret from the model, but **not** from local
  history, so a vault match always marks the handle exposed and asks the user to rotate it. Rewrites keep every original `tool_input` field.
- **Permissive modes:** read `permission_mode` from stdin. In `bypassPermissions`, `dontAsk` or `auto`, `confirm` is treated as `approve`.
- **Agent marker:** `CLAUDECODE=1`. Markers for other agents get recorded here when their adapters are built.

## Consequences

- Golden tests pin these shapes. Phase 3 must capture real payloads for every *verify* item, on macOS, Linux and Windows.
- If `suppressOriginalPrompt` turns out unsupported, SPEC §15's fallback applies.
- Re-verify when the minimum supported Claude Code version changes. `doctor` reports the installed version.
