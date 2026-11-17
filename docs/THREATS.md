# Threat model (SPEC v6)

> Redaction is defense-in-depth, **not** a guarantee. Trust analysis: ADR 0003. Approvals and allow rules: ADR 0007.
> Every row has a leak-suite or integration case, run on Linux, macOS and Windows unless marked.

## Assets

1. Secret values: in the vault, in broker memory, and in an authorized child's env while it runs
2. The DEK and its subkeys: broker memory, and briefly the CLI during auth flows
3. Policy, allow-rule pins, trust records, passkeys (encrypted index)
4. Audit log integrity

## Attacker tiers

| Tier | Who | v1 stance |
|---|---|---|
| T1 | Well-meaning agent making mistakes | Prevent |
| T2 | Prompt-injected agent using generic exfiltration, including forged hook calls and editing files | Prevent, or require a broker-verified human approval |
| T3 | Adaptive agent targeting keygent (binary replacement, shell wrapping, env races, memory tampering) | Out of scope for v1. Detect and document. Phase 6 egress proxy |
| — | Other local users | Prevent |
| — | Model provider and transcript storage | Prevent (values never enter context) |
| — | Root, kernel, physical access | Out of scope |

## Controls

| Threat | Tier | Control |
|---|---|---|
| Agent reads `.env`, vault or runtime dir **via the Read/Grep tools** | T1 (T2 with Claude Code sandbox deny-read) | PreToolUse deny after canonicalization, `permissions.deny`. **A Bash `cat`/`cp` bypasses these**: T2 only if `integrate` configured the sandbox |
| Agent prints env (`env`, `ps e`, `Get-ChildItem env:`) | T1 | denylist. Its own env holds no secrets anyway |
| Agent prints env via an interpreter | T2 | secrets only reach pinned allow-rule binaries or approved commands. Interpreters are never wildcard-allowed |
| Secret echoed in output (raw/b64/hex/pct/JSON/quoted/UTF-16LE) | T1/T2 | broker streaming redactor + PostToolUse pass |
| Approved command transforms the secret (`rev`, XOR, split, exit-code bits) | T2 | **approval is the control**: the human sees the exact command. Redaction cannot catch it |
| **Agent forges `hook pre` to mint and use a grant** | T2 | grants are approved only by broker-observed channels (native UV, `keygent approve`, console passkey) |
| Claude's permission dialog skipped or forged (`confirm` mode) | T1 only | documented. `confirm` is opt-in, and the default is `approve` |
| **PATH or cwd spoofing** (`PATH=/tmp/x`, `./stripe`) | T2 | client env ignored, `argv[0]` resolved to the pinned absolute path + SHA-256, exec without a shell |
| Allowed tool abused with extra flags (`curl -x evil`) | T2 | generic tools never wildcard-allowed. `*` never matches a `-…` argument; `**` needs a `flags` allowlist |
| Agent edits the manifest to grant itself a secret | T2 | `keygent trust` (auth) showing content/diff. Read-once hash |
| Manifest sets a dangerous env name (`LD_PRELOAD`, `NODE_OPTIONS`) | T2 | reserved env-name list |
| Agent loosens policy or edits hooks/settings | T2 | policy changes need auth. Write/Edit deny on settings (UX) |
| Agent speaks the broker protocol directly | T2 | only `Reveal` returns a value, and only with a passphrase proof, under the session key |
| Fake broker receives hook `MatchPrompt`/`Redact` traffic and answers "no match" | T2 | all clients verify the server PID's binary hash and its `broker.lock`; fail closed |
| Redactor flushes a partial secret on idle or progress output | T1 | hold-back rule: bytes that could start a match are never flushed early |
| Script swapped between hash and exec | T2 | the broker executes the exact hashed bytes (memfd / private copy) |
| Agent triggers repeated Touch ID prompts (prompt fatigue) | T2 | `rm` passphrase-only; requester shown; 1 UV prompt per 30 s |
| Agent kills the broker and squats the endpoint | T2 | fixed endpoint location, exclusive bind, mutual auth: the fake gets neither passphrase nor values |
| Agent steers the endpoint via env (`XDG_RUNTIME_DIR`, `TMPDIR`) | T2 | endpoint from fixed OS-provided per-user paths |
| Agent floods the broker with bad auth proofs | T2 | no online passphrase oracle exists (a proof needs the DEK). Per-connection delay only limits flooding. Never auto-seal |
| Agent probes guesses through `Redact`/`MatchPrompt` | T2 | 12 B / **80-bit** minimum (pattern-aware estimator), boolean `MatchPrompt`, rate limits |
| Agent copies `vault.kgt` (e.g. `cp` via Bash) for offline guessing | T2 | **device pepper** in the OS keystore (copy alone is useless), Argon2id 64 MiB/t3/p4, generated passphrase by default. T3 if the agent also extracts the pepper |
| Agent restores an older `vault.kgt` | T2 on Linux/Windows (keystore readable), T3 on macOS | in-memory generation check, OS-keystore tripwire, `rekey` rotates the DEK. **Defeatable by T3** |
| Agent spoofs the console (kills UI, binds the port) | T2 | broker-launched UI, origin bound to that child's lifetime |
| Agent steals the console session | T2 | header token (no cookie), metadata-only, every action needs its own assertion |
| Agent enrolls its own passkey | T2 | enrollment needs a passphrase proof |
| Agent drives the browser (computer use) | T2 | OS UV prompt can't be passed by software |
| Child double-forks to keep the secret | T2 | Job Object, subreaper; macOS run-id sweep (**best effort**) |
| Path deny bypass (case, symlink, 8.3, ADS, `\\?\`) | T2 | canonicalize, then match |
| Human runs `reveal` inside an agent session | T1 | alternate-screen display with auto-clear by default (no scrollback, not in transcript); `--copy` opt-in |
| User pastes a secret into chat | T1 | UserPromptSubmit block. `!!` marks the handle exposed |
| Agent writes a value into source | T1 | PreToolUse Write/Edit via `Redact` |
| Secret in argv / `ps` (visible to OTHER users) | T1/T2 | placeholders and `$SECRET` in argument positions refused by default; `{{keygent-file:…}}`; per-handle `argv = "allow"` opt-in with warning |
| Agent pipes its own input into an approved command (`psql`, `kubectl apply -f -`) | T2 | child stdin is `/dev/null` unless the stored command supplies it; no client stdin frame |
| Agent runs `keygent uninstall --purge` / `integrate --remove` | T2 | passphrase (+ typed confirmation for purge) |
| Agent removes keygent hooks by editing its settings with Bash | T2 known gap | broker still enforces secret use; `doctor` reports missing hooks; Claude Code sandbox write-deny on settings recommended |
| Agent reads the clipboard after `reveal --copy` | T2 known gap | opt-in only, 10 s clear, audited |
| Secret in hook JSON or transcripts | T1 | hooks carry handles and grant ids only |
| Other user connects | — | owner-only dir / SID DACL + peer check |
| Vault tampering (swap entries, edit KDF params) | T2 | AAD binding, slot AAD over the length-prefixed slot fields (no generation), header MAC, capped params |
| Audit edit or truncation | T2 | HMAC chain + anchor in the index |
| Approval of `bash ./x.sh` while the script holds (or later gets) the payload | T2 | script binding: file hashes in the grant key, shown in `approve`, re-checked before exec |
| Approval display spoofing (bidi, ANSI, newlines, zero-width, padding, truncated native prompt) | T2 | `render_for_approval()` escaping. Native prompt only for short plain commands |
| Agent floods bad auth proofs to stall the human | T2 | per-connection delay, correct proofs never delayed, reserved connections |
| Agent floods grants to bury a malicious one among benign ones | T2 | 16 pending max, dedupe, id required with several pending, FIFO prompts |
| Other hooks (e.g. lean-ctx observe) see raw prompts or outputs in parallel | T1/T2 | chain composer: keygent first, observers get blocked or redacted data |
| Human pastes a secret: blocked prompt still stored in local transcript/history | T1 | **Partial by design (non-goal):** the prompt never reaches the model. Vault matches auto-mark exposed + "rotate it". `suppressOriginalPrompt` hides it from the block message only |
| PostToolUse replacement silently ignored (shape mismatch → original output sent) | T1/T2 | exact per-tool schemas + golden tests. Unknown tool → block + exposed. `doctor` self-test. Primary path (`run`) is redacted before Claude Code sees it |
| Agent reads its own transcript/history to recover raw prompts or outputs | T1 (T2 with sandbox) | Read deny + `permissions.deny` for `~/.claude/projects/**` and `~/.claude/history.jsonl`; Bash bypass as above |
| keygent prompt hook broken or timing out lets a pasted secret through | T1 | `onFailure: block` on UserPromptSubmit |
| Secret module types leak into agent-facing code | T1 | `pub(crate)` constructors, no Debug/Clone/Serialize, preflight import gate |
| `confirm` mode silently approved in bypass/auto modes | T1/T2 | treated as `approve` when `permission_mode` is permissive |
| Laptop closed: TTL survives suspend; clock set back | T2 | dual deadlines, seal on wake |
| Crash leaves a stale socket, file bindings or orphans | T2 | lock-file stale detection, crash sweep, PDEATHSIG / Job Object |
| Concurrent writers lose updates; vault on a sync folder | T1 | read-modify-write under lock, broker-only mutations, network/sync FS refused |
| Audit log unwritable (disk full, deleted) | T2 | runs are refused (fail closed) |
| Hibernation image or swap holds broker memory | T3 | disk encryption recommended and checked by `doctor` |
| Injection into the broker | T3 | static musl, hardened runtime, DLL policies, cleared env, OWNER RIGHTS DACL |

## Known gaps (T3 unless noted, all tracked as known failures in the leak suite)

All items below are tagged **`known-gap`** in the leak suite: the test asserts the documented behavior, not prevention (SPEC §14).

0. **T2 residuals (accepted, shown to the human):**
   - **Unbound runs:** anything that isn't purely leaf tools (interpreters, inline code, wrappers, runners, project programs, all
     PowerShell) can execute code keygent can't show. Approvals carry the `⚠ unbound` warning, `--remember` is off, and the native prompt isn't used.
   - **Config steering:** any tool (allowed or approved) reads agent-editable config (`~/.curlrc`, `.npmrc`, `~/.aws/config`,
     kubeconfig, `.git/config`, proxy dotfiles). Mitigated by "config changed since last approval" warnings for known files, and by `home = "scratch"`.
   - **Device pepper** on Linux/Windows is readable by any same-user process, so it protects only against off-box copies.
   - `Redact` inherently confirms a candidate value. The defense is the 80-bit strength floor plus rate limits.
   - Old `backup` files stay decryptable with the old factors after `passwd`/`rekey`.
1. **(T2, was misfiled as T3 before v6) A child's env is readable by same-user processes while it runs:** `/proc/<pid>/environ`, `KERN_PROCARGS2`, PEB via
   `ReadProcessMemory`. Fix: Phase 6 egress proxy. Observed 2026-11-16 ([spike 04](spikes/04-platform-unix.md) §2): readable on Linux and macOS for third-party binaries.
   macOS 26 strips the env of Apple platform binaries (`/usr/bin/curl`) from `KERN_PROCARGS2`. That is undocumented and version-dependent,
   so it's **not** claimed as a control.
2. **(T2 residual since SPEC v6 round 4) Replaced `keygent` / `keygent-ui` binary, PATH shadowing, or a shell alias** can phish the passphrase in the terminal. Native UV and passkey can't be
   phished this way. `doctor` and sensitive commands print the resolved binary path and signature status, and the broker verifies the UI binary
   before launching it.
3. **(T2, alongside gap 1) File bindings** exist as plaintext (memfd on Linux, owner-only temp file on macOS and Windows) for the run's lifetime.
4. **Rollback** of the vault and the keystore tripwire together.
5. **Verify-then-exec TOCTOU** for pinned binaries on macOS and Windows (Linux uses `fexecve`).
6. **Swap exposure** of non-secret-arena broker heap on macOS and Windows (encrypted swap recommended).
7. **macOS containment** is best effort. The env-tag sweep alone misses Apple-binary survivors on macOS 26; session-id sweep proposed in [ADR 0009](adr/0009-macos-session-sweep.md).
8. **Approved commands** can leak through transformations or exit codes (T2, by design the human's call). The approval prompt shows the exact command.
