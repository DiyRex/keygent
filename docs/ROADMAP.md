# Roadmap (SPEC v6)

> **Windows deferred** (owner decision 2026-11-16, [ADR 0010](adr/0010-windows-verification-deferred.md)): macOS + Linux now, Windows compile-checked until a host is available.

Every phase ends with tests **on Linux, macOS and Windows**, the leak suite, and the binary size and idle RSS reported. **Then stop for review.**

## Phase 0 — Spikes & design (no product code)

- [x] Language → [ADR 0000](adr/0000-language.md)
- [x] Trust model + threat tiers → [ADR 0003](adr/0003-trust-model.md), [THREATS](THREATS.md)
- [x] Broker protocol → [ADR 0004](adr/0004-broker-protocol.md)
- [x] Web console → [ADR 0005](adr/0005-web-console.md)
- [x] Cross-platform → [ADR 0006](adr/0006-cross-platform.md), [PLATFORMS](PLATFORMS.md)
- [x] Approvals + pinned allow rules → [ADR 0007](adr/0007-approvals-and-policy.md)
- [x] Operations & lifecycle → [ADR 0008](adr/0008-operations.md), [ERRORS](ERRORS.md)
- [x] Two independent reviews → resolved in SPEC v4 (§17 v3→v4) and v5 (rows 51–74)
- [x] Hook contract (Claude Code 2.1.325) → [ADR 0001](adr/0001-hook-contract.md) — *verify* items confirmed in Phase 3
- [x] Agent env marker `CLAUDECODE=1`
- [x] lean-ctx 3.11 hook behavior + chain composer → [ADR 0002](adr/0002-lean-ctx-composition.md)
- [x] Diagrams → [diagrams/](diagrams/README.md)
- [x] Hooks page read in full; blocked-prompt and output-replacement semantics verified (SPEC v6 rows 75–78)
- [x] Data formats → [FORMATS](FORMATS.md); module/plaintext boundary (SPEC §4.2); native prompt APIs chosen (SPEC §4.3)
- [ ] Platform spike on all three OSes ([checklist](PLATFORMS.md#spike-checklist-phase-0)) — macOS + Linux container done ([spike 04](spikes/04-platform-unix.md), [ADR 0009](adr/0009-macos-session-sweep.md) proposed); Linux desktop VM, Windows, Touch ID from background, WebAuthn open
- [ ] Dependency sizes (`windows-sys`, `libc`, `p256`, crypto set, JSON/TOML, EFF wordlist) → [DEPENDENCIES](DEPENDENCIES.md) — all measured ([spike 03](spikes/03-dep-sizes.md)) except `windows-sys` (needs Windows)
- [x] License: Apache-2.0 (owner decision, matching lean-ctx); weekly advisory workflow added; code signing deferred

## Phase 1 — Vault core

- [x] `Platform` skeleton: locations, network/sync-FS detection, secure files/dirs, atomic replace, `File::lock`, console input, canonical paths — macOS + Linux; Windows fails closed (ADR 0010)
- [x] Format v1: capped header, slot AAD, header MAC, index, independent entries, generation, `.prev`, migrations framework
- [x] KEK slots: passphrase (Argon2id m64/t3/p4) + recovery key; HKDF subkeys; keystore tripwire — file backend (ADR 0011 #1)
- [x] `init [--generate]`, `passwd`, `rekey` (new DEK), `recover`, `verify`, `backup`, `restore [--new-machine]`
- [x] Secrets: `add [--multiline | --from-file]`, `ls`, `rm`, `rename`, `rotate [--undo]`, `edit`, `import [--delete] [--overwrite]`, `reveal` (clipboard) — `--copy` needs a manual check
- [x] Module skeleton per SPEC §4.2 + preflight plaintext-boundary gate
- [x] Strength estimator, grammars, collisions, limits; disk-full safety
- [ ] Unit tests (SPEC §11) — 61 unit + 12 end-to-end pass on macOS and Linux; Windows pending; cargo-fuzz targets pending (tooling)

## Phase 2 — Broker + run

- [x] Unseal handoff, hardening, secret arena + zero-on-free allocator, logging
- [x] Endpoint: fixed paths, exclusive bind, `broker.lock` stale recovery, crash sweep, PDEATHSIG
- [ ] TLV protocol, mutual auth, session encryption, rate limits, reserved connections — *done: protocol, mutual auth, auth-failure + Redact limits, reserved pool; open: session encryption, 2 s auth deadline / 1 reserved per PID (ADR 0014 §8)*
- [x] Dual-clock timers, seal on wake
- [ ] Tokenizers (POSIX, PowerShell), placeholder rewrite, dialect rules — *POSIX + rewrite done (M3); PowerShell waits for Windows (ADR 0010)*
- [x] Allow rules (pin + `flags` allowlist), grants + grant key + **script binding** + `render_for_approval()`, `pending`/`approve`/`deny` — *ADR 0014, 0015*
- [x] Run: containment, pipes-only env, runtime/output caps + `--max-runtime` (≤ 4 h, in grant key), `\r` flush, redactor (old values kept after rotate) — *ADR 0014; LANG/TZ not yet passed*
- [x] Manifest trust, `capture`, audit chain (fail closed) — *ADR 0015; open: audit rotation, tripwire anchor, rekey epoch record, trust diff, global manifest*
- [ ] Leak harness + T1/T2 cases

## Phase 3 — Claude Code integration

- [ ] Hooks per ADR 0001 (capture real payloads for every *verify* item on 3 OSes); `onFailure` + `if` filter
- [ ] PostToolUse: exact `updatedToolOutput` schema per built-in tool + golden tests per Claude Code version; `doctor` self-test
- [ ] Read deny for Claude Code transcripts/history; prompt-paste → exposed flow
- [ ] Chain composer (`--chain`, `integrate chain`), unchained-observer detection
- [ ] Native approval prompts (macOS LAContext via objc2; Windows only if the Phase 0 per-request-text spike passed), helper-process fallback, FIFO queue, desktop notification
- [ ] Policy modes incl. permissive-mode handling, denylist
- [ ] `integrate claude`, `uninstall`, skill, `permissions.deny`, `doctor` + `--report`, `version`
- [ ] Golden tests (hooks, ERRORS.md); full T1/T2 leak suite on all OSes
- [ ] *(ADR 0016, proposed)* Prempti coexistence (parallel PreToolUse observer, `doctor` detection, false-positive canaries); Prempti sensitive-path union + canonical matching; `policy export --format cedar|json|falco`; staged rules (`enforcement = audit`); `audit --export ocsf|coding-agent`

## Phase 4 — Web console

- [ ] Broker-launched, verified `keygent-ui`; passkeys; approvals via `render_for_approval()`; management; headless URL mode

## Phase 5 — lean-ctx + distribution

- [ ] `integrate lean-ctx` (chain composer), allowlist + secret paths
- [ ] `install.sh` / `install.ps1` (cosign-verified), Homebrew tap, signed + notarized + Authenticode releases, third-party notices

## v1 Definition of Done (Phases 0–5)

See SPEC §14.

## Owner-requested tracks (2026-11-28, proposed — each lands as its own small PR, verified before the next)

**DO token slice** ("make a DO droplet" without the token in chat)
- [ ] S1 Tool binding: `keygent edit <h> --tool doctl` pins the program; the broker injects the handle's env name; e2e with a fake tool
- [ ] S2 Claude Code `PreToolUse` hook rewrites to `keygent run --grant <id>` (contract verified per ADR 0001)
- [ ] S3 Native Touch ID approval on macOS (LAContext, broker-rendered text)
- [ ] S4 Web console: loopback random port, passkeys (Touch ID / Windows Hello), write-only value entry, gated reveal, approvals (ADR 0005 amendment)

**Env sets** ([ADR 0019](adr/0019-env-sets.md))
- [ ] Index `sets` table + `set add|rotate|edit|rm|ls`, dotenv paste entry, tier/aliases
- [ ] Manifest `[sets] use = […]`, one approval per set, prod tier never `allow`
- [ ] `run --env-file` private binding; leak tests (no value in project files, dotenv override)
- [ ] Skill text: alias resolution, ask on ambiguity, never pick prod

**Audit v2** ([ADR 0018](adr/0018-audit-log-v2.md))
- [ ] v2 records (observed vs reported fields, agent, tool) + encrypted `x` field
- [ ] `audit` filters/ranges, `audit stats --by …`, `--follow`, `--json`
- [ ] Segments: rotation (4 MiB / 30 d), DEFLATE, `segments.idx`; retention (400 d / 128 MiB, 90 d floor), prune checkpoint, archive dir
- [ ] `audit export|verify --archive`, `backup --with-audit`; alerts; console Audit page

**Release** ([ADR 0017](adr/0017-release-pipeline-and-updates.md))
- [ ] GoReleaser config + manual-only `release.yml` (snapshot/release), formula generator — branch `build/goreleaser`, verified with a local snapshot
- [ ] Public tap `DiyRex/homebrew-tap` + `HOMEBREW_TAP_TOKEN` (owner)
- [ ] Windows targets once `src/platform` builds there

**Reviews feeding these** — [RustyVault comparison](research/rustyvault-comparison.md): revoke approved grants and `--remember`
entries on tightening edits; Shamir (recovery key only) in Phase 6. Cedar: [ADR 0020](adr/0020-cedar-policy.md), owner decision.

## Later

- **Phase 6 — Hardening:** egress proxy (T3), screen-lock seal, passkey PRF unseal, user-presence slots, Shamir, MCP
  - *(ADR 0016, proposed)* egress = placeholder custody (mode R base-URL default, mode C name-constrained ephemeral CA opt-in), PDP/CDP split, host binding + SSRF guard, 403 + audit on mismatch; spikes first: TLS client size, CA env matrix; optional child confinement (Landlock/seccomp, Seatbelt, Job Object); DPoP ADR
- **Phase 7 — Ecosystem:** other agent adapters, external backends, winget/scoop
  - *(ADR 0016, proposed)* `SecretBackend` + OpenBao via pinned local `bao proxy` socket (AppRole secret in vault, wrapped bootstrap, per-run leases revoked at exit); `minted` handles (CB4A Model B); `import --sops`; OpenShell credential driver only as a separate binary after its own ADR
