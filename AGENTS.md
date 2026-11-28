# AGENTS.md — keygent

Guide for any AI coding agent working in this repo (Claude Code, Codex, Cursor, Gemini, …).

## What this is

`keygent` is a small local Rust CLI that lets AI coding agents **use** secrets without **seeing** them.
The agent only sees handles (`stripe/live`). Values exist only inside the **broker** process and the environment of
the one child it launches for an authorized command. Everything that child prints is redacted before the agent reads it.
It runs on macOS, Windows and Linux.

Start here: [`docs/diagrams/01-system-architecture.excalidraw`](docs/diagrams/) → SPEC §3 (trust model) → ADR 0003, 0004, 0006.

- Full spec, and the source of truth: [`docs/SPEC.md`](docs/SPEC.md)
- Phase tracker: [`docs/ROADMAP.md`](docs/ROADMAP.md)
- Decisions: [`docs/adr/`](docs/adr/)
- How to contribute: [`CONTRIBUTING.md`](CONTRIBUTING.md) · Security policy: [`SECURITY.md`](SECURITY.md)

## Current status

**Pre-alpha.** Phases 0–2 (design, vault core, broker + `run`) are merged into `main`. Phase 2's leak harness (M5) and the
Windows platform layer are still open; no release has been cut yet.
Progress is tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Working rules

1. **Work one phase at a time** (SPEC §12). At the end of each phase, run the tests and the leak suite and report the binary size and idle RSS.
   Then **stop and wait for review**. Do not start the next phase on your own.
2. **Verify, don't remember.** External contracts (Claude Code hook schema, env markers, lean-ctx
   behavior) must be checked against current docs or a real run, and recorded in an ADR with the version checked.
3. **If the spec is wrong, say so.** If something in the spec is impossible or unsafe, write it down and propose an alternative. Never deviate silently.
4. **Use std first.** Every new crate needs one line in [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md):
   its size impact and why std is not enough. Measure the size before and after.
5. **Keep diffs small.** Change only what the current phase needs.

## Security rules (hard, no exceptions)

- **Never use real secrets** in code, tests, fixtures, logs, commit messages or chat. Use generated canaries
  `KEYGENT_CANARY_<random>`.
- **Assume the AI agent is the same OS user** (ADR 0003). Hooks, TTY checks, env markers and the socket peer check are
  **not** security boundaries. Anything that matters is enforced in the **broker**.
- **Only the broker holds plaintext.** No broker request returns a value, except CLI `Reveal` after a passphrase proof, under the
  session key. Hooks rewrite commands to `keygent run --grant <id>` (no command text). The broker spawns children itself and returns
  redacted output. Plaintext never appears in hook stdout/stderr/JSON, argv, logs, audit records, errors, panic messages,
  test snapshots or `Debug` impls. Secret types implement neither `Debug` nor `Display` (or print `‹redacted›`), and zeroize on drop.
- **Allowlist, not denylist.** Secrets reach only pinned allow-rule binaries (absolute path + SHA-256, exec without a shell,
  client env ignored) or commands a human approved.
- **Approvals are observed by the broker** (native UV with broker text, `keygent approve` + passphrase, console passkey).
  Never trust a client or hook that says "approved". Claude Code's dialog is the T1-only `confirm` mode (ADR 0007).
- **Fail closed in the broker.** If redaction fails or the vault state is unknown, withhold the output and return a one-line error.
- **No custom crypto.** Use only the RustCrypto crates: `chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`, `p256` (verify only), `zeroize`, `getrandom`.
- **Auth is the gate** for add, reveal, rotate, rm, edit/policy, import, trust, approve and passkey enrollment. TTY and agent-marker checks are UX only.
- **The design baseline is SPEC v6.** A change needs an ADR and a row in SPEC §17. Data formats live in `docs/FORMATS.md`.
- **Plaintext boundary:** only `crypto/`, `vault/`, `broker/`, `redact/` (and `cli/` during auth) may use `Secret`/`Dek`/`Subkey`.
  `hook/`, `adapter/`, `policy/`, `proto/`, `ui/` must not (SPEC §4.2, enforced by `preflight.sh`).
- **keygent goes first.** Any other tool's hook on prompts, Bash/PowerShell or tool output is chained behind keygent (ADR 0002).
- **Approvals bind what actually runs:** the command, cwd, program and script file hashes. Every display goes through `render_for_approval()`.
- **Never log values, commands or prompts** (broker.log, audit). Exit codes and messages come from `docs/ERRORS.md`.
- **Every security claim names its attacker tier** (T1/T2/T3, see docs/THREATS.md).
- **`unsafe` is denied crate-wide.** The only exception is `src/platform/`, where it is allowed per block with a `// SAFETY:` comment.
- Never run the real `keygent integrate claude` against your own `~/.claude` while developing. Use a temp
  `HOME` (see `tests/leak/README.md`).

## Tech constraints (summary of SPEC §4)

| Item | Budget |
|---|---|
| Language | Rust stable, edition 2024, **no async runtime** (threads + blocking I/O) |
| Release binary (every target) | ≤ 3 MB hard, ≤ 2 MB target (ADR 0023) |
| Unsealed broker idle RSS | ≤ 5 MB |
| Hook invocation p95 | ≤ 30 ms (≤ 50 ms on Windows) |
| `keygent run` overhead | ≤ 10 ms, redaction ≥ 200 MB/s |
| Platforms v1 | **Linux, macOS, Windows** (x86_64 + arm64). Every phase must pass tests on all three ([PLATFORMS.md](docs/PLATFORMS.md)) |
| Device safety | no admin/root, per-user only, no services, loopback-only, contained children, clean uninstall (SPEC §3.3) |

Diagrams live in `docs/diagrams/` and are generated by `python3 docs/diagrams/build.py`. Update the script when the design changes.

## Planned layout (mirrors SPEC §4.2, which is canonical)

```
src/
  main.rs        # arg parsing + dispatch only
  crypto/        # RustCrypto wrappers; Secret/Dek/Subkey types (pub(crate) constructors)
  proto/         # broker TLV frames (no plaintext types)
  cli/           # subcommand handlers incl. the thin `run`/`capture` client and the mutual-auth client
  vault/         # format, slots, index, entries, migrations, lock; the local `SecretBackend`
  broker/        # unsealed daemon: sole holder of plaintext; grants, approvals, policy, spawner, timers, audit chain
  redact/        # streaming multi-pattern redactor (constructed only by broker/)
  policy/        # tokenizers, allow-rule matching, denylist, render_for_approval() — no plaintext
  hook/          # hook prompt/pre/post + chain composer — no plaintext
  adapter/       # AgentAdapter impls (claude; stubs for others) — no plaintext
  platform/      # ONLY place for unsafe/FFI: `Platform` trait + unix.rs, linux.rs, macos.rs, windows.rs
  ui/            # keygent-ui web console (cargo feature `ui`, separate binary)
tests/
  leak/          # adversarial leak suite (canaries)
fuzz/            # cargo-fuzz targets (redactor, hook JSON)  — created in Phase 2
docs/            # SPEC, ROADMAP, ADRs, THREATS, SECURITY, DEPENDENCIES, spikes
scripts/         # size-check, latency, rss checks
```

## Commands

```sh
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check          # licenses, bans, advisories (covers cargo audit)
scripts/size-check.sh     # fails if target/release/keygent > 3 MB
```

## Output style for agent-facing text

- One line, prefixed with `keygent:`, at most 120 chars, and it names the exact next action.
  Example: `keygent: vault sealed — ask the user to run 'keygent unseal'`
- Happy path emits nothing (zero tokens).
- Exit codes: `77` = policy deny, `78` = vault sealed. Otherwise pass through the child's exit code.

## Docs conventions

- Write an ADR for any decision that is hard to reverse, or that rests on an external contract. Copy
  [`docs/adr/TEMPLATE.md`](docs/adr/TEMPLATE.md) and number it sequentially.
- Raw spike notes, commands and measurements go in `docs/spikes/`. The conclusions go in the ADR.
- Keep `docs/ROADMAP.md` checkboxes current.

## Commits

Use gitmoji commit titles (e.g. `✨ add vault header parser`), followed by a short body of key points.
Never include secret values or canaries in commit messages.
