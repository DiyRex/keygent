# ADR 0008 — Operations and lifecycle

- **Status:** accepted
- **Date:** 2026-11-15
- **Verified against:** second independent design review (gaps 4–15). Details live in SPEC v5 §4.1, §5.2, §5.4, §5.12 and §12.

## Context

v4 defined the security model but not how keygent is installed, upgraded, recovered, configured, diagnosed or removed, or which
environments it supports. Several of those gaps were security-relevant: lost passphrases, concurrent writers, stale sockets after a crash,
audit write failures, and timers during suspend.

## Decision (summary)

| Area | Decision |
|---|---|
| Recovery | Recovery-key KEK slot at `init` (shown once, typed back). `passwd`, `recover`, `verify`. `vault.kgt.prev` kept. Per-entry isolation |
| Concurrency | One broker per user (Unix) or per logon session (Windows). Mutations go through the broker while unsealed. Read-modify-write under `File::lock`. Network/sync FS refused |
| Crash | `broker.lock` for stale-socket detection. Run-dir sweep + `KEYGENT_RUN_ID` sweep on start. `PR_SET_PDEATHSIG` on Linux |
| Failure | Disk full leaves the vault intact. Audit append failure means runs are refused (fail closed) |
| Time | Dual monotonic + wall deadlines. Seal on wake after a suspend longer than the idle timeout. Backward clock steps never extend a deadline |
| Upgrade | Stable launcher path in hooks. Version lock with quiet hook behavior. Forward-only format migrations with a `.pre-vN` backup. `restore --new-machine` |
| Config | UX-only `config.toml`. Security settings in the encrypted index (auth to change). Env vars may only tighten |
| Diagnostics | `broker.log` (never values, commands or prompts), `version`, `doctor` checklist, `doctor --report` (paste-safe) |
| Errors | Exit codes 64/75/76/77/78/79 + `keygent:` line. Catalog in ERRORS.md, golden-tested |
| Distribution | `install.sh`/`install.ps1` with cosign verification, Homebrew tap, `cargo install`. winget/scoop later. Windows user-PATH edit is the single §3.3 exception, with consent |
| Uninstall | Seal → stop → remove integrations, skill, runtime, config, log, tripwire → binary (delayed delete on Windows). The vault and audit log are kept unless `--purge` |
| Environments | Desktops: full. WSL2: Linux, no native prompt. SSH/headless: approve from a 2nd terminal. Containers: per-container vault. CI: unsupported in v1 |
| License | Owner decision pending. Third-party notices via `cargo-about` |

## Consequences

More Phase 1–2 scope (recovery, verify, migrations, timers, logging). This is accepted because each item either prevents data loss or closes a
fail-open path.
