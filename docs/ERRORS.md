# Errors and exit codes

Every keygent-originated failure prints exactly one line to stderr, starting with `keygent:` (≤ 120 chars, names the next action), and
exits with one of the codes below. `keygent run` otherwise passes through the child's exit code. Use the `keygent:` line to tell the two
apart. Golden tests pin every line. Exit `1` is used only by human-facing commands and by `capture` when overwriting needs auth
(never by `run`), for failures that need no special handling by an agent. The text in this table is canonical; ADR 0004 refers here.

| Exit | Protocol code (ADR 0004) | Message | Next action |
|---|---|---|---|
| 64 | — | `keygent: usage: <short usage>` | fix the command |
| 75 | `ApprovalDenied` | `keygent: approval denied or timed out for <handle>` | ask the user, then retry |
| 76 | `NotTrusted` | `keygent: .keygent.toml changed — ask the user to run 'keygent trust'` | user runs `trust` |
| 77 | `PolicyDenied` | `keygent: <handle> is not allowed for this command — ask the user to approve or add a rule` | user decides |
| 77 | `PolicyDenied` | `keygent: blocked — this command would print secrets` | use a handle instead |
| 78 | `Sealed` | `keygent: vault sealed — ask the user to run 'keygent unseal'` | user unseals |
| 79 | `VersionMismatch` | `keygent: updated — run 'keygent seal' then 'keygent unseal'` | user re-unseals |
| 79 | `Internal` | `keygent: broker error <code> — run 'keygent doctor'` | user runs doctor |
| 79 | — | `keygent: audit log unwritable — run 'keygent doctor'` | user runs doctor |
| 79 | `RateLimited` | `keygent: too many requests — retry in a few seconds` | wait |
| 79 | `TooLarge` | `keygent: input too large (limit <n>)` | split the input |
| 1 | `NeedsAuth` | `keygent: this needs your passphrase — run it in your own terminal` | human runs it |
| 1 | — | `keygent: value too weak to redact safely — rotate it at the provider to a longer one` | rotate |
| 1 | — | `keygent: vault is format <n> — upgrade keygent` | upgrade |
| 1 | — | `keygent: disk full — vault unchanged` | free space |
| 1 | — | `keygent: vault on a network/sync folder is not supported — move it with 'keygent restore'` | move vault |
| 74 | — | `keygent: run stopped at its limit (<n> min / 10 MiB) — use --max-runtime or run_in_background` | narrow the command or request more time |
| 77 | `PolicyDenied` | `keygent: a program or script changed after approval — re-run to request approval again` | re-run |
| 77 | `PolicyDenied` | `keygent: can't approve runs from this folder — run inside a project` | cd into the project |
| 79 | `RateLimited` | `keygent: approval queue full — retry in a minute or ask the user to run 'keygent pending'` | retry later |
| 77 | `PolicyDenied` | `keygent: secret would be visible in the process list — use {{keygent-file:<h>}} or a tool that reads $KEYGENT_<H>` | rewrite the command |
| 77 | `PolicyDenied` | `keygent: placeholder inside single quotes won't expand — use double quotes` | rewrite the command |
| 75 | `ApprovalDenied` | `keygent: approval timed out in the queue — retry` | retry |

## Human-facing messages added in Phase 1 (exit 1 unless noted; golden-tested in `src/error.rs`)

| Exit | Message |
|---|---|
| 1 | `keygent: passphrase too weak — use 16+ chars and 5+ random words, or the generated one` |
| 1 | `keygent: wrong passphrase — nothing changed` |
| 1 | `keygent: wrong recovery key — nothing changed` |
| 1 | `keygent: no vault yet — run 'keygent init'` |
| 1 | `keygent: a vault already exists — use 'keygent passwd' or 'keygent restore'` |
| 1 | `keygent: <handle> not found — check the handle` |
| 1 | `keygent: <handle> already exists — use 'keygent rotate' to change it` |
| 1 | `keygent: name clashes with <handle> — pick another handle` |
| 64 | `keygent: invalid handle — use lower-case a-z 0-9 . _ - and up to 4 '/' parts` |
| 64 | `keygent: invalid env name — use A-Z 0-9 _ (max 64)` |
| 1 | `keygent: env name <NAME> is reserved — pick another` |
| 1 | `keygent: value must be 12 bytes to 64 KiB` |
| 1 | `keygent: vault damaged — run 'keygent verify'` |
| 1 | `keygent: this device's key is missing — run 'keygent recover' with your recovery key` (SPEC §5.2) |
| 1 | `keygent: vault is older than expected (rolled back?) — nothing changed` |
| 1 | `keygent: unsafe <what> (owner, mode or symlink) — run 'keygent doctor'` |
| 1 | `keygent: not a regular file owned by you` |
| 1 | `keygent: confirmation didn't match — nothing changed` |
| 1 | `keygent: cancelled — nothing changed` |
| 1 | `keygent: nothing to undo for <handle> (only within 24 h of a rotate)` |
| 1 | `keygent: backup belongs to a different vault — use 'restore --new-machine'` |
| 1 | `keygent: <feature> is not supported on this platform yet` |
| 1 | `keygent: file error <code> — run 'keygent doctor'` |
| 79 | `keygent: internal error <code> — run 'keygent doctor'` |

Handles and env names inside messages are cut to 48 characters so every line stays ≤ 120 chars.

## Messages added in Phase 2 (golden-tested in `src/error.rs`)

| Exit | Protocol code | Message |
|---|---|---|
| 77 | `PolicyDenied` | `keygent: <handle> is not in the vault — run 'keygent ls' for handles` |
| 77 | `PolicyDenied` | `keygent: a script must be a regular file ≤ 16 KiB inside the project to be approved` |
| 64 | `BadRequest` | `keygent: can't parse this command — check its quotes and placeholders` |
| 64 | `BadRequest` | `keygent: --remember isn't available for this run (it runs code keygent can't fully show)` |
| 79 | — | `keygent: broker could not be verified — run 'keygent doctor'` |
| 79 | — | `keygent: too many or too large secrets to redact safely — remove some or split vaults` |
| 79 | `Audit` (12) | `keygent: audit log tampered at record <n> — run 'keygent doctor'` |
| 79 | `Audit` (12) | `keygent: audit log truncated or its anchor doesn't match — run 'keygent doctor'` |
| 76 | `NotTrusted` | (row above) — also when a command references a manifest name and the manifest isn't trusted as-is |
| 1 | — | `keygent: no .keygent.toml here or above (up to the repo root)` |
| 1 | — | `keygent: .keygent.toml line <n> is not valid — only version and [secrets] entries` |
| 1 | — | `keygent: .keygent.toml is too large or not UTF-8 (max 64 KiB)` |
| 1 | `Failed` (13) | broker-relayed human-facing lines (e.g. a captured value too weak); `capture` onto an existing handle → `NeedsAuth` |
| 1 | — | `keygent: no pending requests` |
| 1 | — | `keygent: several requests pending — pass an id from 'keygent pending'` |
| — | — | `keygent: waiting for approval — ask the user to run 'keygent approve'` (stderr notice from `run`, not an error) |

`run` relays broker errors as the canonical line plus a protocol code. The new code `RunLimit` = 11 maps to exit 74 (ADR 0014 §11).
