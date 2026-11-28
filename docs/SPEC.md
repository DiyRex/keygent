# keygent — sealed secrets broker for AI coding agents

> **SPEC v6 — design baseline (2026-11-15).** Source of truth. Any change needs an ADR and a row in [§17](#17-revision-log).
> v5 added the verified hook contract, lean-ctx composition and operations. v6 adds the **fully verified** hook semantics
> (blocked prompts and tool-output replacement), concrete data formats ([FORMATS](FORMATS.md)), the module/plaintext boundary,
> native-prompt implementation, multi-line secrets, long-running processes and explicit non-goals.
> Companions: [PLATFORMS](PLATFORMS.md) · [THREATS](THREATS.md) · [ERRORS](ERRORS.md) · [FORMATS](FORMATS.md) · [diagrams](diagrams/README.md) ·
> ADRs [0003](adr/0003-trust-model.md) trust · [0004](adr/0004-broker-protocol.md) protocol · [0005](adr/0005-web-console.md) console ·
> [0006](adr/0006-cross-platform.md) platforms · [0007](adr/0007-approvals-and-policy.md) approvals · [0008](adr/0008-operations.md) operations.

---

## 0. Working rules

1. Work phase by phase (§13). At the end of each phase, run tests on **Linux, macOS and Windows** plus the leak suite, report the binary size and idle RSS, then stop for review.
2. Verify external contracts against docs or real runs, and record them in an ADR (ADR 0001 items marked *verify* must be confirmed by a captured payload).
3. Never use real secrets. Use canaries `KEYGENT_CANARY_<random>`.
4. Use std first. Every dependency gets a line in `docs/DEPENDENCIES.md`.
5. If the spec is wrong, say so. Never deviate silently.

## 1. Problem

Giving an agent a credential today means pasting it into chat or letting it read `.env`. Either way the value reaches the model
provider and the transcripts, and can be echoed back later.

## 2. Goal

The agent sees **handles** (`stripe/live`), never values. Plaintext exists only in the **broker** and in the environment of the one
child process the broker launches for an **authorized** command. Output is redacted before the agent reads it. This is the same on macOS,
Windows and Linux.

### 2.1 Non-goals (v1)

- **Team sharing or sync** of vaults between people or machines (each machine has its own vault; `backup`/`restore` moves one).
- **Multiple vaults/profiles** per OS user.
- **CI / unattended use** (no passphrase-in-env by design).
- **Credential-helper protocols** (git, docker, npm credential helpers, ssh-agent). Possible in Phase 7.
- **Writing secrets into config files** for apps. Apps read env vars or a `file = true` binding at run time; keygent never renders
  plaintext into files the agent can read.
- **Interactive TTY programs** through `run` (pipes only).
- **Protecting a secret the human pastes into chat from local Claude Code files.** keygent keeps it from the model provider and marks it
  exposed, but Claude Code may still store it in the local transcript and prompt history (ADR 0001 #5).
- **A sandbox.** keygent is not one (T3 is out of scope for v1).
- **Hiding a running command's environment from same-user processes.** While an authorized command runs, `ps eww` or
  `/proc/<pid>/environ` can read its env. That is a generic one-liner, so it's a **known T2 gap** in v1, and the egress proxy (Phase 6) is the fix.
  Mitigations: the T1 denylist, short runs, and a warning in the approval for `--max-runtime` > 5 min.

---

## 3. Trust model

### 3.1 Attacker tiers (ADR 0003)

The agent runs **as the same OS user**. It can connect to any socket or pipe the user can, run any subcommand (including forged
`keygent hook …`), fake a TTY, edit user files (manifests, scripts, settings, rc files, user-writable binaries), and read
same-user process environments.

| Tier | Attacker | v1 stance |
|---|---|---|
| **T1** | Well-meaning agent making mistakes | Prevent |
| **T2** | Prompt-injected agent using *generic* exfiltration: env dumps, `curl evil`, interpreters, forged hook calls, editing manifests/scripts, spoofing prompts, flooding the broker | Prevent, or require a **broker-verified human approval of exactly what will run** |
| **T3** | Adaptive agent targeting keygent itself (binary replacement, shell wrapping, env races, memory tampering) | Out of scope for v1. Detect and document. Egress proxy in Phase 6 |

Every security claim names its tier.

### 3.2 Principles

1. **Only the broker holds plaintext.** The only response that carries a value is CLI `Reveal` after a passphrase proof,
   under the session key.
2. **Hooks are UX and defense in depth.** Claude Code runs hooks in parallel, treats crashes and timeouts as non-blocking, and the
   agent can call any subcommand. Every decision that matters is enforced **in the broker**. Static `permissions.deny` rules
   (which apply in every permission mode) are the backstop.
3. **Authorization uses factors the agent cannot produce:** the passphrase (mutual challenge-response), OS user verification raised
   by the broker, and a passkey on the broker-launched console. A grant is approved only through these channels.
4. **The human approves exactly what keygent can bind, and is told what it can't.** That means the command text, cwd, injected env
   names, **every** resolved program (path + hash), and the **full content** of any script file it executes. Code the script loads
   transitively (imports, sourced files, `make`, `npm run`) can't be bound, and the prompt says so (§5.5.2).
5. **Allowlist, not denylist.** Secrets reach only pinned allow-rule programs or approved commands.
6. **Secrets go into env vars or private file bindings, never argv.** Any command where a secret would be expanded into a program's
   arguments (a placeholder or `$SECRET_ENV` in an argument position) is **refused by default**, because argv is visible to *other* local
   users via `ps`/`/proc/<pid>/cmdline`. The safe forms are: the tool reads the env var itself, or `{{keygent-file:<handle>}}`, which expands to the
   path of a private file binding (e.g. `curl -H @{{keygent-file:stripe/hdr}}`). A per-handle `argv = "allow"` (set with auth) opts back in,
   with a warning in every approval.
7. **Children get no input the human didn't approve.** stdin is `/dev/null` (`NUL`) unless the approved command text itself supplies it
   (a pipe or heredoc inside the stored command).
8. **Fail closed in the broker.** This covers redaction errors, unknown state, protocol errors, limit breaches and audit write failures.
9. **keygent goes first.** Any other hook that sees prompts, commands or tool output is chained **behind** keygent, so it only
   sees blocked or redacted data (§5.10.2).
10. **Honest claims, frugal tokens.** Nothing is emitted on the happy path. Each agent-facing message is one line, ≤ 120 chars, starts with `keygent:`, and names the next action.
11. **Same guarantees on every OS** through native primitives (PLATFORMS.md). `doctor` reports wherever an OS is weaker.

### 3.3 Device safety

keygent never needs admin/root. It never installs services, drivers, kernel extensions or startup items, never edits shell rc
files or system config (it edits agent settings only, with a backup and `--remove`), and never listens on anything but loopback (console only).
It makes no outbound connections and sends no telemetry. It never changes how other programs run (children get default process state). It leaves
no orphans (containment, best effort on macOS), runs within its limits (§4.1), and leaves no trace after `uninstall`. **The one exception:**
the Windows installer script may add its own install dir to the *user* `PATH`. It asks first, and `uninstall` removes it.

---

## 4. Tech constraints

- Rust stable, edition 2024, **MSRV 1.89**. Single binary (plus `keygent-ui`, feature `ui`). No async runtime.
- Targets: linux x86_64/arm64 (static musl), macOS arm64/x86_64, Windows x64/arm64 (static CRT).
- Budgets: binary ≤ 2 MB per target; broker idle RSS ≤ 5 MB; hook p95 ≤ 30 ms (≤ 50 ms Windows); `run` overhead ≤ 10 ms; redaction ≥ 200 MB/s.
- Crypto: RustCrypto only (`chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`, `p256` verify), `zeroize`, `getrandom`. MAC and token comparisons are constant-time.
- FFI only in `src/platform/` (`libc`, `windows-sys`). Secret types have no `Debug`/`Display`. No panics on untrusted input. Every input has a limit.

### 4.1 Limits and defaults

| Item | Value |
|---|---|
| Handle | `^[a-z0-9][a-z0-9._-]{0,62}(/[a-z0-9][a-z0-9._-]{0,62}){0,3}$`, ≤ 1 000 per vault |
| Secret value | 12 B – 64 KiB, strength ≥ **80 bits** by the §5.3 estimator |
| Passphrase | `init` **generates** a 6-word EFF passphrase by default (≈ 77 bits). `--own-passphrase` requires ≥ 16 chars, ≥ 70 estimated bits, and not in the embedded common-password list |
| Env name (manifest) | `^[A-Z_][A-Z0-9_]{0,63}$`, not reserved (§5.6) |
| Frame / output chunk | 1 MiB / 64 KiB |
| Connections | 32 total, **5 reserved**: 4 for the `auth`/`control` classes, 1 for hook `MatchPrompt`. A reserved `auth` connection must present a valid `Auth`/`UvAuth` within **2 s**, otherwise it's closed. Max **1 reserved connection per peer PID**. `control` is limited to `Seal`/`Status`/`Deny` |
| Concurrent runs | 8 |
| Pending grants | 16 total, max 4 per **(uid, cwd)**, deduplicated by grant key. At the cap a new request evicts the **oldest pending request from the same cwd**. `deny --all` clears them. The quota protects availability only and is not a security boundary |
| Approval wait | **90 s from when the prompt is shown**, and at most **5 min from grant creation** (queued grants age out). The hook sets the Bash tool `timeout` to ≥ 150 s. A run whose grant expires in the queue exits 75 (`approval timed out`) |
| Auth failure | **1 s delay on that connection only**. Global cap of 30 failures/min, after which *failed* proofs get `RateLimited`. A correct proof is never delayed or rejected. Never auto-seal. (There is no online passphrase oracle: a proof needs the DEK, so the delay only limits flooding.) |
| `Redact` / `MatchPrompt` | `Redact`: 20 requests/s and 16 MiB/s per connection, 64 MiB/s global. `MatchPrompt`: 20/s. A `Redact` hit inherently confirms a candidate value, so the defense is the 80-bit strength floor |
| Session | `unseal --ttl` default 8 h (max 24 h), idle timeout 30 min |
| Run | max runtime 30 min by default. A command may request `--max-runtime` up to 4 h (dev servers, watchers); the requested runtime is part of the grant key and shown in the approval. Max output 10 MiB per stream for foreground runs (then truncated with a one-line notice). Long-running runs stream without an output cap but keep the runtime cap |
| `--remember` | 15 min, keyed by grant key (§5.5.2) |
| Console session | 15 min, metadata only |
| Audit / broker log | rotate at 10 MB × 5 / 1 MB × 3 |
| Hook timeout (installed) | 5 s (`timeout` field). UserPromptSubmit 5 s |

Hook latency budgets exclude chained third-party hooks (§5.10.2), which are measured and reported separately by `doctor`.

All deadlines carry **both a monotonic and a wall-clock expiry**. Either one passing means expired, and a wall clock stepping backward never
extends a deadline. If the wall-vs-monotonic gap shows a suspend longer than the idle timeout, the broker **seals on wake**.
Checks run on every request and on a 30 s ticker.

### 4.2 Module architecture and the plaintext boundary

One crate, one binary (plus `keygent-ui`). Modules and who may touch what:

| Module | Responsibility | May hold plaintext? |
|---|---|---|
| `platform/` | OS primitives behind `trait Platform` (the only `unsafe`/FFI) | locked-arena allocation only |
| `crypto/` | thin wrappers over RustCrypto: KDF, AEAD, HKDF, HMAC, constant-time compare | yes (keys) |
| `vault/` | file format (FORMATS §1–2), slots, index, entries, migrations, locking | yes |
| `broker/` | daemon: protocol server, auth, grants, approvals, policy, spawner, timers, audit | yes |
| `redact/` | automaton build + streaming matcher | yes (patterns), constructed **only** by `broker/` |
| `policy/` | tokenizers, allow-rule matching, denylist, `render_for_approval()` | **no** (works on commands, not values) |
| `proto/` | TLV frames, request/response types | **no** (except the `Sealed` ciphertext type) |
| `cli/` | argument parsing, human prompts, mutual-auth client | only during auth flows (DEK in the locked arena) |
| `hook/` + `adapter/` | hook JSON in/out, chain composer, Claude adapter | **no** |
| `ui/` (feature) | console HTTP server, static assets | **no** |

**Type-level boundary:** `Secret`, `Dek` and `Subkey` are defined in `crypto/` with **`pub(crate)` constructors**. They implement
`Zeroize` + `Drop`, never `Debug`/`Display`/`Clone`/`Serialize`, and can't be formatted. `hook/`, `adapter/`, `policy/`, `proto/` and `ui/`
must not import them. A CI lint (`cargo deny`-style import check, a simple `grep` gate in `preflight.sh`) enforces this.

### 4.3 Native approval prompt implementation (no heavy dependencies)

- **macOS:** `LAContext.evaluatePolicy(.deviceOwnerAuthentication, localizedReason:)` called through the Objective-C runtime
  (`objc2` + `objc2-local-authentication`; size measured in Phase 0). Result is a local boolean observed **in the broker process**.
- **Windows (Phase 0 pass/fail):** the prompt **must show per-request text**. `NCRYPT_UI_POLICY` is a key property set at creation, so a
  long-lived Passport KSP key can't do that, and any same-user process could raise the same dialog. Candidates for the spike:
  `UserConsentVerifier.RequestVerificationForWindowAsync` (per-call message, via minimal hand-written WinRT/COM bindings, no `windows`
  crate), or a short-lived per-grant Passport key whose description is the rendered request, signing `H(grant_key ‖ nonce)`.
  **If neither passes, Windows has no native channel in v1** (terminal and console only).
- **Linux:** none (no root-free system prompt). Uses `keygent approve` or the console.
- If the API can't be raised from the windowless broker, a short-lived helper process (`keygent __prompt`) spawned by the broker raises it
  and returns the result over an inherited pipe (SPEC §15).

---

## 5. Architecture

Diagram 01 shows the components, diagram 03 the `run` flow, diagram 05 the unseal handoff and authentication, and diagram 09 hook composition.

### 5.1 Commands

| Area | Commands | Auth |
|---|---|---|
| Vault | `init [--own-passphrase]`, `unseal [--ttl] [--log]`, `seal`, `status`, `passwd`, `rekey`, `recover`, `verify`, `backup <file>`, `restore <file> [--new-machine]` | passphrase for init/unseal/passwd/rekey/restore. Recovery key for `recover`. `seal`/`status` need none. **`verify`**: while unsealed it runs in the broker and returns metadata only (bad handles, MAC status); while sealed it needs the passphrase. **`ls`** while sealed exits 78 |
| Secrets | `add [--multiline \| --from-file <path> [--delete]]`, `rotate [--undo] [same input flags]`, `rm`, `rename`, `edit`, `import .env [--delete] [--overwrite]` | **auth** |
| Reveal | `reveal <handle> [--copy]` | passphrase proof. **Shows the value on the terminal's alternate screen and clears it after 20 s or a keypress** (default), so it doesn't stay in scrollback. `--copy` uses the concealed clipboard instead, cleared after 10 s. Any same-user process can read the clipboard (`pbpaste`/`Get-Clipboard`), so that's a known **T2** gap. Every reveal is audited |
| Approvals | `pending`, `approve [<id>] [--remember]`, `deny [<id> \| --all]` | `approve` needs auth. **With several pending grants an id is required. There is no batch approve** (`deny --all` exists) |
| Agent-safe | `ls`, `run --grant <id>`, `run [--dialect] [--max-runtime] -- <cmd>`, `capture`, `check <cmd>`, `audit [--since] [--verify]`, `exposed [--mark <handle>]`, `untrust`, `version` | none (policy is enforced in the broker; `--mark` can only add exposure) |
| Project | `manifest init`, `manifest add …`, `trust` | `trust` shows the content or diff, then needs auth |
| Console | `ui`, `passkey add`, `passkey ls`, `passkey rm` | passkey add/rm need a passphrase proof |
| Integration | `integrate claude [--project] [--remove]`, `integrate lean-ctx [--remove]`, `integrate chain <event> <cmd>`, `doctor [--report]`, `uninstall [--purge]` | none for agent-settings edits (reversible, with backups). **Recording shell paths and the install binary hash needs auth** |
| Hooks | `hook prompt`, `hook pre`, `hook post` (each optionally with `--chain <cmd>`) | none |
| Removing protection | `integrate … --remove`, `integrate chain`, `uninstall`, `uninstall --purge` | **passphrase** (refused under agent markers as UX). `--purge` deletes the vault and audit log, so it asks you to type `delete my vault` as well. Note: a T2 agent can still edit its own settings files with Bash to drop the hooks. That's a known gap; the broker still enforces policy and `doctor` reports missing hooks |
| Internal | `broker`; `mcp` (**Phase 6**) | — |

**auth** = a mutual passphrase challenge-response. Broker-raised OS user verification is accepted only for the short actions listed in §5.5.1.
`reveal` is passphrase-only, everywhere.

**Value input:** `add` reads one line with echo off by default. `--multiline` reads until a line containing only `.`, for PEM keys
and JSON. `--from-file` reads a file (≤ 64 KiB, regular file, owned by the user), then offers to delete it (`--delete` to do so without
asking). File input is how service-account JSON and certificates get in. The file path is never logged.

### 5.2 Vault format and keys (diagram 04)

- `vault.kgt` in the per-OS data dir, owner-only, one vault per OS user. **Refused on network or sync filesystems** (NFS, SMB, iCloud
  Drive, OneDrive or Dropbox folders), because locking is unreliable there.
- Header (plaintext, authenticated): magic `KGNT`, format version, vault UUID, `generation` (u64), KEK slots. **Each slot carries its own
  KDF id + params + salt** (so `passwd` can use a fresh salt without touching the recovery slot). KDF params are **capped** (m ≤ 256 MiB,
  t ≤ 10, p ≤ 8), checked before any KDF runs. Slot = `XChaCha20-Poly1305(KEK, DEK)`, slot AAD = `SHA-256(enc(magic) ‖ enc(format_version)
  ‖ enc(uuid) ‖ enc(slot fields except nonce and ciphertext))`. **No `generation` in it**, so the broker (which holds only the DEK) can write
  the vault without re-wrapping slots. `generation` and the slot list are covered by `header_mac`.
- **Exact derivations** (all HKDF-SHA256, `enc` = FORMATS length-prefixed encoding):
  - passphrase KEK = `HKDF(salt = uuid, ikm = enc(Argon2id(passphrase, slot_salt; m,t,p)) ‖ enc(pepper), info = "kg/v1/kek/passphrase")`
  - recovery KEK = `HKDF(salt = uuid, ikm = recovery_key, info = "kg/v1/kek/recovery")`
  - subkeys = `HKDF(salt = uuid, ikm = DEK, info = "kg/v1/key/<entry|index|hdr|audit|auth|broker>")`
  - `passwd` writes a fresh `slot_salt`. Golden vectors in `tests/golden/crypto/`.
- **KEK slots:** `passphrase` and **`recovery`**.
  - Passphrase slot: Argon2id m=64 MiB, t=3, p=4, mixed with the **device pepper**, a random 32-byte value stored in the macOS Keychain
    (ACL for the signed keygent binary), DPAPI CurrentUser on Windows, and on Linux via `secret-tool` (absolute path) if a Secret Service is
    running, otherwise an owner-only file `~/.local/state/keygent/device.key` kept **outside** the vault dir (exclude it from backups). **What it protects:** a
    vault copied **off this machine** (backups, sync, stolen disk image) can't be guessed offline without it. **What it doesn't:** on Linux and
    Windows any same-user process can read it with a one-liner, so against an on-box agent it's T2-equivalent and **passphrase strength
    is the real barrier**. Only macOS (signed builds) adds a per-app ACL. **No keystore** (headless Linux, WSL without Secret Service):
    the pepper lives in the owner-only state-dir file above (never in the data dir next to the vault; `backup` verifies it is not included), and `doctor` says so. **Pepper lost** (keystore reset): `unseal` says
    `keygent: this device's key is missing — run 'keygent recover' with your recovery key`. `restore --new-machine` uses the recovery key.
  - Recovery KEK: a random 256-bit key shown once at `init` as Base32 in 8 groups **plus a 2-character checksum group**. The user must
    type it back to confirm. No pepper (it's already uncrackable). Later: passkey PRF, OS user-presence.
- Keys: random DEK → HKDF-SHA256 → `K_entry`, `K_index`, `K_hdr`, `K_audit`, `K_auth`, `K_broker`. Header MAC = `HMAC(K_hdr, header)`.
- **Index** (handles, metadata, policy, pins, trust records, passkeys, security settings, audit anchor, previous values for 24 h): AEAD
  under `K_index`, AAD = `uuid ‖ "index" ‖ generation`. **Entries:** AEAD under `K_entry`, AAD = `uuid ‖ handle ‖ version`. Entries are
  independent, so one corrupt entry never bricks the vault.
- **Writes:** read-modify-write under `File::lock`. Reload the index, apply the change, write the temp file in the same dir, fsync, atomically replace, fsync the dir.
  Before replacing, the current file is kept as **`vault.kgt.prev`**, **except** after `passwd`, `rekey`, `rm`, `rotate`, `recover` and any
  **security-tightening** change (`edit` policy, `untrust`, removing an allow rule, `passkey rm`).
  Those delete `.prev` and every `.pre-v<N>` once the new file is durable, so old factors or old values don't linger. (Overwriting is best
  effort on SSD/APFS/CoW; old `backup` files stay decryptable with the old factors, and the CLI warns about that.) Stale `*.tmp` files are swept on start. On disk full, the original
  stays intact and the user gets `keygent: disk full — vault unchanged`.
- **Who writes:** while unsealed, **every mutation goes through the broker**. While sealed, the CLI writes directly under the lock.
- **Rollback:** in-memory generation check plus an OS-keystore tripwire `(uuid, generation)`. On a mismatch `unseal` **refuses** unless the
  human confirms in the terminal with the passphrase (`keygent: vault is older than expected (rolled back?) — confirm to continue`).
  Defeatable if the tripwire is rolled back too (T3 on macOS; T2-reachable on Linux and Windows, where the keystore has no per-app ACL).
- **Integrity on reload:** every broker reload re-verifies `header_mac` under `K_hdr`. A failure (another writer with a different DEK) seals the broker.
- **Factor changes are exclusive:** `passwd`, `rekey` and `recover` first ask every running broker (all sessions) to seal, and refuse while any
  is still running. `rekey` writes an audit **epoch record** signed by the old `K_audit` and naming the new chain's first MAC, so the chain stays verifiable.
- **`passwd`** replaces the passphrase slot (same DEK). **`rekey`** creates a new DEK, re-encrypts everything, **generates and confirms a
  new recovery key** (the old one stops working) and drops the 24-h previous values (use it after a suspected compromise). **`recover`**
  takes the recovery key, sets a new passphrase and runs `rekey`.
- **`verify`** checks the header MAC, the index and every entry, and reports bad entries by handle (no values). It offers to restore `.prev`.
- **Format versions:** a newer format is refused (`keygent: vault is format N — upgrade keygent`). Migrations first write
  `vault.kgt.pre-v<N>` and are forward-only.
- `backup` is a byte copy. `restore` checks the UUID and tripwire. **`restore --new-machine`** clears the tripwire, pinned executables, shell paths
  and passkeys (all device-bound), and sets every handle to `approve`.

### 5.3 Identifiers and strength

- Placeholder env: `KEYGENT_` + upper-case handle with `/ . -` → `_`. Collisions (compared case-insensitively) are refused at `add`/`rename`.
- **Strength estimator** (deterministic, shared by secrets and passphrases; a pattern-aware estimator in the style of zxcvbn, without its large dictionaries):
  1. Reject outright anything in the embedded **common-password list** (top 10 000, ~80 KB) after normalizing case and leetspeak.
  2. Split the value into segments and score each one at its cheapest interpretation: a dictionary word (EFF list + common list) = log2(list
     size) + 1 bit for capitalization + 1 bit per leet substitution; a year (1900–2099) or date = 7 bits; a keyboard walk or
     sequence/repeat run = log2(length × 10); **a non-dictionary run of letters only = 2 bits/char** (human text is low-entropy); anything
     else (mixed classes) = `len × log2(charset of that segment)`.
  3. The total is the sum. Golden vectors: `Passw0rd!2024` ≈ 30 bits (refused), `john.smith1985` ≈ 40 (refused), a 32-char random
     base62 API key ≈ 190 (accepted).
  4. `--own-passphrase` must score ≥ 70 **and** be ≥ 16 chars, which in practice means ≥ 5 random words or a password-manager-generated string.
- A weak secret is refused with `keygent: value too weak to redact safely — rotate it at the provider to a longer one`.
- **Agent markers** (UX only): `CLAUDECODE=1` (verified, ADR 0001), plus the markers recorded for other agents in ADR 0001.
- **Build id** = `semver + git commit + target triple`, embedded at build time. Shown by `keygent version`.

### 5.4 Broker lifecycle (diagram 05)

- **Unseal:** read the passphrase from the console with echo off, run Argon2id, unwrap the DEK locally, spawn `keygent broker` with a cleared env and **one inherited pipe**
  (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` on Windows), send the DEK, zeroize.
- **Hardening:** no dumps or debugger, injection defenses, OWNER RIGHTS process DACL on Windows. Secrets live in a **locked arena**
  (if it can't be locked, the broker **refuses to start**). Everything else is freed through a **zero-on-free** allocator. Linux additionally
  tries `mlockall(MCL_CURRENT|MCL_FUTURE)`, and if `RLIMIT_MEMLOCK` is too low it **degrades to arena-only**, with a `doctor` warning.
  Broker threads use 128 KiB stacks. In each child's pre-exec, rlimits (incl. `RLIMIT_CORE`) and the signal mask are **reset to the values
  captured at unseal**, so children get default process state.
- **Linux home lookup:** `getpwuid` (musl reads `/etc/passwd` only). If the user isn't there (SSSD/LDAP), keygent falls back to `$HOME`
  **only if** that dir is owned by the uid and not group/world-writable, and `doctor` notes the fallback.
- **Scope:** one broker **per OS user on Linux and macOS**, one **per user and logon session on Windows** (RDP and fast user switching). All agent
  sessions share it.
- **Endpoint:** a fixed OS-provided per-user location (PLATFORMS.md), owner-only, **exclusive bind**. A `broker.lock` file in the run dir is
  held for the broker's lifetime. If the socket exists, `connect` is refused and the lock is free, the socket is stale: the broker unlinks and rebinds it.
- **Clients verify the broker (all clients, including hooks and `run`):** the client gets the server's PID (`SO_PEERCRED` on Linux,
  `LOCAL_PEERPID` on macOS, `GetNamedPipeServerProcessId` on Windows). The broker writes `{pid, process start time, exe path}` into
  `broker.lock` while it holds the lock. The client checks that the peer PID and its start time (which defeats PID reuse) match the lock
  file, that the lock is actually held (a non-blocking lock attempt fails), and that the PID's executable is the installed keygent binary
  (path + hash recorded at install). Residual: a same-user race between those checks is T3. If verification fails, unauthenticated clients **fail
  closed, scoped like the version lock**: `run` refuses; `hook pre` denies **only** commands with placeholders, manifest env refs or allow-rule
  matches (other commands pass untouched); `hook post` blocks the output **only if** a generic detector fires, otherwise it passes the output
  and adds a "broker unverified" notice once; `hook prompt` blocks only on generic-detector hits and adds the same notice. A fake broker therefore
  can't silently disable redaction or prompt blocking, and a broken one doesn't stop normal work.
- **Binary identity across upgrades:** signed builds are pinned by **signature identity** (macOS Developer ID team, Windows Authenticode
  subject, cosign identity for Linux tarballs), so upgrades need no re-pin. Unsigned or source builds are pinned by hash, and **`unseal` re-pins**
  (it already holds the passphrase) after showing the old and new hash. Until then, clients fail closed as above.
- **Private-dir checks (all fallback dirs, incl. macOS `/tmp/keygent-<uid>` and the Linux `~/.local/state/keygent/run/`):** `lstat` before
  bind **and** before every client connect: not a symlink, owner = uid, mode 0700 (Windows: owner-only protected DACL). Otherwise refuse with
  `keygent: unsafe runtime dir <path>`.
- **Crash recovery:** on start, sweep the run dir (leftover file bindings, tmp files) and kill processes still carrying a stale
  `KEYGENT_RUN_ID`. Direct children get `PR_SET_PDEATHSIG` (Linux). The Job Object covers Windows. macOS is best effort.
- **Seal:** on `seal`, TTL, idle, wake after a long suspend (§4.1), SIGTERM/SIGHUP or logoff. Sealing zeroizes and exits.
- **Version lock:** a client and broker with different build ids get `VersionMismatch`. Hooks then deny only commands containing placeholders, and print
  `keygent: updated — run 'keygent seal' then 'keygent unseal'` at most once per day. Otherwise they stay silent.
- **Logging:** `state/broker.log`, owner-only, rotated. It holds events, error codes and timings, **never values, commands or prompts**. Level is set with
  `unseal --log=info|debug`. Panics log a fixed string plus file:line, then abort.

### 5.5 Authentication and approvals (ADR 0007)

#### 5.5.1 Mutual re-auth

The CLI unwraps the DEK locally (locked memory) and derives `K_auth`/`K_broker`. The broker proves itself first, then the CLI proves itself
(ADR 0004). Values travel under `K_sess`. A squatting fake broker gets nothing.

**OS user-verification auth** (`UvAuth{action, canonical_params_hash}`) is allowed **only** for actions the broker can describe completely
in ≤ 200 rendered chars and that aren't destructive: `approve` of a short bound grant, and `rename`. **`rm` needs the passphrase.**
(`deny` and `untrust` need no auth at all, because they only reduce access.) The broker builds the prompt text itself, including the **requesting process name and cwd**, and rate-limits UV prompts to
**1 per 30 s** (prompt-fatigue defense). On **Windows** the native channel is enabled only if the Phase 0 spike proves **per-request prompt
text** (§4.3). Otherwise Windows approvals use terminal or console.
Everything else needs the passphrase in the terminal, where the human's own CLI shows the full content before asking. **`trust`** shows the full
manifest or diff, **`edit`** shows the policy diff, and **`add`/`rotate`/`import`** take value entry. **`reveal`** needs a fresh passphrase proof only,
everywhere (never UV, never console). The broker refuses `Trust`/`EditPolicy` frames that don't carry the hash of the content the CLI displayed.

#### 5.5.2 Grants and approvals

- A grant is created by `hook pre` (`GrantCreate{cmd, dialect, cwd}`), or by `run` invoked directly with a command. **The grant stores
  the command**, and `keygent run --grant <id>` carries no command text at all, so the outer shell can't split or reinterpret it (§5.7).
  **Grant key** = `SHA-256` over a length-prefixed encoding of: canonical command, dialect, cwd, handles, **every resolved executable
  (path + SHA-256)**, script files (path + SHA-256), and requested max runtime. Grants are **single-use**: consumed by the first `Run`.
- **cwd rule:** the cwd is canonicalized and must be inside the **project root**. For hook-created grants that root is
  `CLAUDE_PROJECT_DIR` from the hook environment (set by Claude Code, not by the agent's shell). `/`, the home dir, drive roots and system
  dirs are always refused. For direct `keygent run` (no hook) the root is the nearest ancestor with `.git`/`.keygent.toml`. An agent can
  create one of those anywhere, so for direct runs this rule is **UX only**, and the approval shows the root path.
- **Executable binding:** the tokenizer finds every command word (pipelines, `&&`, subshells). Each is resolved against the PATH captured
  at unseal, hashed, shown in the approval, and **re-checked before exec** (fails closed on a mismatch). Hashing runs **off the hook path**
  (`GrantCreate` returns immediately, and the prompt appears once hashing finishes). Results are cached by (dev, inode, size, mtime, **ctime**)
  on Unix, since ctime can't be set by users. On Windows the cache applies only to files the user can't write (e.g. `Program Files`); user-writable
  executables are re-hashed every time.
- **Bound vs unbound (allowlist-shaped, per subcommand).** A run is **bound** only if **every** command word is a **leaf tool invocation
  that matches that tool's shipped grammar** (permitted subcommands and flags, the same shape as §6.2 allow rules), with no wrapper, inline code
  or script. The grammars ship with keygent and are tested, and they cover inline-code arguments as well as files: for example
  `doppler run …`, `kubectl exec|debug|cp|plugin`, `helm --post-renderer`, `gcloud … ssh --command`, `psql -c '\…'`, `mysql -e '\!…'`,
  `aws … --cli-input-* file://` are **outside** the grammar, so they're unbound. Tools with grammars in v1: `stripe`, `aws`, `gcloud`, `az`,
  `kubectl`, `helm`, `gh`, `psql`, `mysql`, `redis-cli`, `curl`/`wget` (without `-K`/`--config`/`-q` overrides). Any pinned allow-rule
  invocation is bound by its own rule. Arguments after a `--` that hands off to another program (`doppler run --`, `kubectl exec --`) are
  always unbound. **File inputs** in a leaf tool's argv or redirects (`@file`, `file://…`, `-f/--file/--input/--data-binary @…`,
  `< x`, heredocs) are read once, hashed, shown in full (≤ 16 KiB) and executed from those exact bytes. They make the run **unbound** when the
  tool can execute what it reads (`psql`/`mysql` scripts with `\!`/`\i`/`SOURCE`, `kubectl apply/exec` and kubectl plugins, `gh alias`/
  `gh extension`, `helm` with local charts). That per-tool "executes embedded code" list ships with keygent and is tested. **Everything else is unbound**: interpreters (including `-c`/`-e` inline code), wrappers (`timeout`,
  `env`, `nice`, `nohup`, `xargs`, `find -exec`, `sudo`, `git` aliases), runners (`make`, `npm`/`npx`/`pnpm`/`yarn`, `cargo run`,
  `python -m`), project-local programs and **all PowerShell**. Unbound approvals show
  `⚠ unbound — this runs code keygent can't fully show (project files, imports, wrappers). Approve only if you trust this project.`
  `--remember` is **never** offered for them. Interpreters run in isolated mode where the runtime supports it (`python -I`,
  `PYTHONSAFEPATH`, `node --disable-proto=throw` is not relied on).
- **Script binding (for what can be bound):** a script named directly (`bash x.sh`, `./x.sh`, `python x.py`, `node x.js`,
  `source x`) must be inside the project root, regular, ≤ **16 KiB**. The broker reads it **once**, hashes those bytes, and **executes
  exactly those bytes** (Linux memfd → `/dev/fd/N`; macOS/Windows an owner-only copy in the broker run dir, passed to the interpreter), so
  swapping the script on disk after approval has no effect. A shebang interpreter (`#!/usr/bin/env node`) is resolved and bound like any
  executable. A script run is still **unbound** (its imports aren't).
- **Config steering (applies to every run, not only allow rules):** tools read agent-editable config (`~/.curlrc`, `~/.netrc`,
  `.npmrc`, `~/.aws/config` incl. `credential_process`/`endpoint_url`, kubeconfig, `.git/config`, proxy settings).
  - **Bound runs default to `home = "scratch"`**: an empty temp HOME and XDG dirs, plus the tool's config env vars pointed at empty paths. A
    handle or rule can opt into `home = "inherit"` with auth.
  - For `inherit` runs and unbound runs, the per-tool config table (shipped and tested) lists the files the tool reads. **On the first
    approval of a tool**, every existing config file is shown (path, size, mtime, hash), and approval must happen in terminal or console.
    Afterwards, a change since the last approval shows `⚠ ~/.curlrc changed since you last approved curl` and disables the native prompt.
- **Channels** (all verified by the broker): a native UV prompt raised by the broker (macOS LocalAuthentication; Windows only if the
  §4.3 spike passes), `keygent approve` with a passphrase proof, or a console passkey. Claude Code's dialog is the T1-only `confirm` mode.
  Every terminal passphrase prompt first prints the **resolved path and signature status of the running `keygent` binary**. A shim or alias
  that captures the passphrase is a documented **T2 residual** (THREATS), mitigated by the sandbox write-deny that `integrate` configures on
  the launcher dir and shell rc/profile files (`doctor` **fails** when it's absent), and by preferring native UV and console approvals for routine use.
- **Rendering** is one broker function, `render_for_approval()`, used by every channel, audit and `pending`:
  - Control characters, newlines, ANSI escapes, bidi controls, zero-width characters and non-ASCII are escaped as `\u{…}`, with a `⚠ non-ASCII` flag.
  - It always shows the cwd, the injected env names, the resolved program/shell, the script files (path, size, first 8 hex of hash), the length,
    and the first 8 hex of the grant key.
  - **The native prompt is used only** when the run is **bound**, the rendered command is ≤ 200 chars, it has no escapes, and no tracked config changed.
    Otherwise it says `"<handle>: approve in terminal or console (command too long / special characters / runs project code)"`, and approval
    must happen in `keygent approve` or the console. Both show the full escaped command and the **entire content of every bound script**,
    and **approval is refused until the human has paged to the end**.
  - The prompt shows a banner `N other requests pending`.
- **Multiple pending grants:** native prompts are queued FIFO, one at a time. Wait, lifetime and quota are defined **only in §4.1**.
  `approve` without an id works only if exactly one is pending, and `deny --all` clears the queue. The
  `Approve` frame carries `grant_id` **and the grant-key hash the CLI displayed**, and both are bound into the auth proof, so the human approves what they saw.
  After 5 s, a blocked `run` sends one desktop notification through the OS notification API (no install needed).
- `--remember`: 15 min for the **same grant key**. Never for unbound runs.
- **Timing:** wait limits are in §4.1. The hook sets the Bash tool's `timeout` in `updatedInput` to
  `min(600 000, (original timeout or 120 000) + 90 000 + 30 000)` ms, which covers approval plus the original run budget (runs longer than the
  Bash tool's 10-min maximum must use `run_in_background`). An approved but unconsumed grant is reused by grant key if the agent retries. A full queue
  returns `RateLimited` (exit 79), not "denied".

### 5.6 Project manifest and trust

```toml
[secrets]
"stripe/live" = { env = "STRIPE_API_KEY" }
"gcp/sa"      = { env = "GOOGLE_APPLICATION_CREDENTIALS", file = true }
```

- A manifest grants nothing until `keygent trust` (auth), which shows the full file the first time and a diff afterwards. The broker reads the file once, then
  hashes and parses that same buffer. Any change un-trusts it.
- Reserved env names are refused: `PATH`, `PATHEXT`, `HOME`, `USERPROFILE`, `SHELL`, `ComSpec`, `SystemRoot`, `IFS`, `ENV`,
  `BASH_ENV`, `PROMPT_COMMAND`, `SHELLOPTS`, `LD_*`, `DYLD_*`, `NODE_OPTIONS`, `PYTHON*`, `PERL5*`, `RUBYOPT`,
  `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `GIT_*`, `SSH_*`, `KEYGENT_*`, `TERM`, `PAGER`, `EDITOR`, `VISUAL` (the exact list lives in code and is tested).
- Global manifest: `config/global.toml`, with the same rule. The upward search stops at the repo root.
- File bindings: memfd on Linux. On macOS and Windows a random name in the owner-only run dir, deleted on exit and swept after a crash.

### 5.7 `keygent run -- <cmd>` (diagram 03)

Two invocation forms. **The client environment is ignored** in both:

- `keygent run --grant <id>`: the form hooks produce. The client sends only `{grant}`, and the broker runs the command **stored in the grant**.
- `keygent run [--dialect d] [--max-runtime t] -- <cmd>`: direct use. The client sends `{cmd, dialect, cwd}`, and the broker creates the grant itself.

The dialect comes from the hook (`Bash` → POSIX, `PowerShell` → pwsh), or from `--dialect`. Otherwise it is POSIX (Windows: Git Bash if
recorded, else pwsh). It is never guessed from env. Long runs (dev servers, anything over the Bash tool's own timeout) must use Claude Code's
`run_in_background`. The skill says so.

1. **Parse** with the dialect tokenizer (POSIX or PowerShell; `cmd.exe` unsupported).
2. **Resolve handles:** placeholders, plus trusted-manifest bindings referenced by env name or matched by an allow rule.
3. **Decide** (§6): an allow rule, an approved grant (re-check script hashes), or deny (exit 77).
4. **Execute.**
   - **Allow-rule path (env-only):** a single simple command with **no placeholders and no shell metacharacters, globs, `~` or `$`**. Secrets
     arrive only through env bindings (manifest or handle `env_name`). The broker runs the pinned program path + SHA-256 (`fexecve` on Linux), exec
     **without a shell**, with the tokenized argv. A placeholder makes a command ineligible, so it goes to `approve`.
   - **Approved path:** the fixed dialect shell (absolute path recorded with auth), started **without rc or profile files**: `sh` with
     `ENV` unset, `bash --noprofile --norc`, `pwsh -NoProfile -NonInteractive`. Every bound executable is re-checked first. Windows
     `.cmd`/`.bat` targets are refused (argument-escaping flaw class).
   - **Placeholder forms:**
     - `{{keygent-file:<h>}}` → the absolute path of a private file binding holding the value (safe anywhere in argv).
     - `{{keygent:<h>}}` in an **argument position** → **refused** (`keygent: secret would be visible in the process list — use
       {{keygent-file:…}} or a tool that reads $KEYGENT_X`), unless the handle has `argv = "allow"`. Then it is rewritten by quote context
       and the approval warns `⚠ value visible to other local users in the process list while it runs`.
     - `{{keygent:<h>}}` in a **non-argv position** (assignment `X={{keygent:h}} cmd`, heredoc body piped to stdin) → rewritten by quote
       context and stays in env/stdin.
     - The same argv check applies to manifest env names referenced as `$NAME` in argument positions.

     | Context | POSIX | PowerShell |
     |---|---|---|
     | unquoted word | `"${KEYGENT_X}"` | `$env:KEYGENT_X` |
     | inside `"…"` | `${KEYGENT_X}` (stays inside the quotes) | `$($env:KEYGENT_X)` |
     | inside `'…'`, quoted heredoc, here-string `@'…'@` | **refused**: `keygent: placeholder inside single quotes won't expand — use double quotes` | refused |
     | unquoted heredoc / `@"…"@` | `${KEYGENT_X}` | `$($env:KEYGENT_X)` |

   Both paths use:
   - a canonical, user-owned cwd
   - the minimal env allowlist plus authorized secrets, plus `TERM=dumb`, `NO_COLOR=1`, `PAGER=cat`, `GIT_PAGER=cat`, `KEYGENT_RUN_ID`
   - **pipes only, no PTY.** A program that requires a TTY fails with its own error. **stdin is `/dev/null` (`NUL`)** unless the stored
     command supplies input itself. The protocol has no client stdin frame (§3.2.7)
   - containment
   - limits: as in §4.1 (default 30 min and 10 MiB per stream; `--max-runtime` up to 4 h; long runs without an output cap)
5. **Stream** through per-stream redactors. **Hold-back rule:** bytes that are a prefix of any pattern's still-possible match are never
   emitted until the match completes or becomes impossible. Newline, `\r` and 50 ms idle flushes release **only bytes that can't start a
   match**. EOF releases everything (with matches redacted). After `rotate`, the redactor keeps the **old value** until seal.
6. **Forward** interrupts and return the exit code. The descendant tree is killed at the end, **and immediately if the client disconnects**
   (for example when Claude Code's Bash tool times out). A run killed by the runtime or output cap exits **74** with a `keygent:` line.
7. **Audit** (if the audit append fails, the run is refused: `keygent: audit log unwritable — run 'keygent doctor'`).

Files the child writes (e.g. `-o out.json`) are not redacted on disk. If the agent reads them later, the PostToolUse pass catches known encodings (documented).

### 5.8 Redactor

Per secret it matches raw, base64 std/url (3 alignments, ± padding), hex, percent, JSON-escaped, shell-quoted, UTF-16LE, and the value
with quotes or whitespace stripped, all in one Aho-Corasick automaton. **Multi-line values** (PEM, JSON) also register each line ≥ 20
chars **that scores ≥ 60 bits on its own** (so structural lines like `"type": "service_account",` aren't registered), the base64 body
re-wrapped at 64 and 76 columns, and the body unwrapped into one line.
**Size cap:** the automaton is limited to **8 MiB** of pattern bytes (reference vault: 200 handles averaging 200 B, about 1.5 MiB, within the
5 MB idle RSS budget). `add`/`import`/`rotate` that would exceed the cap are refused with
`keygent: too many or too large secrets to redact safely — remove some or split vaults`, and `unseal` refuses a vault over the cap. Generic detectors: AWS, GitHub, Stripe, Slack, JWT, PEM.
Tokens: `‹keygent:<handle>›` / `‹keygent:unknown›`. Property tests and fuzzing.

### 5.9 `capture <handle> -- <cmd>`

The only value-inbound path the agent can trigger. It **creates only** (overwriting needs auth), the command itself must pass policy, new
handles default to `approve`, and it stores stdout (trimmed). The agent **can't choose the env name**: it is always the default
`KEYGENT_<HANDLE>`, and the human can change it later with `edit`. The reserved-name check (§5.6) applies to **every** `env_name`, wherever it is set. For JSON output, use the producing tool's own selector (e.g. `--query`), because keygent has no JSON selector.

### 5.10 Hooks (Claude Code adapter, verified in ADR 0001)

#### 5.10.1 Events

| Event | Behavior |
|---|---|
| `UserPromptSubmit` | **Sealed or broker unreachable:** run the generic detectors locally; on a hit block, otherwise allow (once per session, it adds a one-line notice to the block reason or `additionalContext` that vault matching is off). Prompts over 1 MiB are chunked, never blocked for size. **Unsealed:** `MatchPrompt` over the reserved connection (boolean, plus a separate "matched a vault value" flag). On a match: `{"decision":"block","reason":"Looks like a secret — it was NOT sent. Claude Code may keep it in local history, so rotate it. Store it with 'keygent add <name>' in your own terminal.","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}`. The prompt never reaches the model. `suppressOriginalPrompt` only keeps it out of the block message: Claude Code may still write it to the local transcript and prompt history (verified, ADR 0001). So a match on a **vault value always marks that handle `exposed`**, override or not. A `!!` override sends the prompt to the model and also marks it exposed. Never prints to stdout on exit 0. Hook entry uses `onFailure: "block"` (a broken keygent blocks prompts rather than letting secrets through; `doctor`/`uninstall` remove the entry). |
| `PreToolUse` `Bash\|PowerShell` | **Trigger:** while unsealed, every Bash/PowerShell command gets one `Check` round trip (local IPC, < 2 ms, inside the hook budget). The command is rewritten only when it has a placeholder, references a trusted-manifest env name, or matches an allow rule. If the broker is sealed or unreachable, nothing is rewritten, so the raw command runs **without** secrets and fails safely. For a match: `GrantCreate{cmd, dialect, cwd}`, then `updatedInput` = the **full original `tool_input`** with `command` replaced by **`'<absolute launcher path>' run --grant <id>`** (no command text, so there's nothing for the outer shell or a wrapper to split, and it never depends on PATH). **User permission rules are preserved:** before rewriting, the hook evaluates the *original* command against the user's Claude Code `permissions.deny`/`ask` rules (Bash rule syntax). A deny match → `deny`, an ask match → `ask`. Otherwise the hook returns `permissionDecision: "allow"` for the rewrite, because keygent's own approval is the real gate and Claude's dialog would only show an opaque grant id. `integrate` also adds `Bash('<launcher>' run --grant *)` to `permissions.allow` as a backstop. An allow-rule match makes the broker pre-approve the grant. `confirm` handles add `permissionDecision: "ask"`. **If `permission_mode` is `bypassPermissions`, `dontAsk` or `auto`, `confirm` is treated as `approve`.** T1 denylist hits get `deny`. Otherwise nothing is emitted. |
| `PreToolUse` `Write\|Edit\|MultiEdit\|NotebookEdit` | Deny if the content contains a vault value (`Redact`), or if the target is the manifest, keygent config, agent settings/hooks or a shell rc file. |
| `PreToolUse` `Read\|Grep\|Glob` | Deny the vault, runtime dir, `.env*`, key files, and **Claude Code's own transcripts and prompt history** (`~/.claude/projects/**`, `~/.claude/history.jsonl`, which may hold raw prompts or outputs) after canonicalization. Backstop: `permissions.deny` (`Read(//<abs>/**)`, `Read(~/…)`), which applies in every mode and also covers Edit/Write. **These rules cover the file tools only. A Bash `cat`/`cp` gets around them, so on their own they're T1.** They become T2 when `integrate claude` also configures **Claude Code's sandbox** filesystem deny-read for the same paths (*verify* setting names in Phase 3). `doctor` reports whether the sandbox is active. The device pepper (§5.2) keeps a copied vault uncrackable either way. |
| `PostToolUse` `*` | `Redact` (chunked). If anything changed, return `updatedToolOutput` **built to the exact schema of that tool's `tool_response`**. Claude Code silently **ignores a mismatched shape and sends the original** (verified), so keygent supports a fixed set of built-in tools with per-version golden tests. For a tool whose schema it doesn't know, it returns `decision: "block"` with a one-line reason **and** marks the handle exposed (the output may already be visible). MCP tools use `updatedToolOutput` (no schema validation). `doctor` runs a live self-test that the replacement takes effect. This is the second layer: `keygent run` output is redacted before Claude Code ever sees it. |

Installed hooks use the absolute path of a **stable launcher** (`~/.local/bin/keygent`, or `%LOCALAPPDATA%\Programs\keygent\keygent.exe`),
exec form on Windows, and `timeout: 5`. Failure mode (`onFailure`, Claude Code ≥ 2.1.295): **`block`** for `UserPromptSubmit`, and for
`PreToolUse Bash|PowerShell` restricted with `if` to commands containing `{{keygent:` (*verify* the `if` pattern in Phase 3). **`continue`**
everywhere else, so a broken keygent never stops normal work. The broker is the enforcement point, and `permissions.deny` is the backstop.
Hooks see the `permission_mode` field. Under `auto`, a hook's `ask` still reaches the prompt (verified). Under `bypassPermissions`/`dontAsk`
it is undocumented, so `confirm` is treated as `approve` in those modes.

#### 5.10.2 Composition with other hooks (ADR 0002)

Matching hooks run **in parallel**, and how several `updatedInput` results combine is undocumented. Other tools' observers therefore see raw prompts and
outputs. **keygent must go first:**

- `keygent hook <event> --chain '<other hook command>'` runs keygent's logic, then the chained hook, and merges:
  - **prompt:** if keygent blocks, the chained hook is **not called**. Otherwise it is called with the original payload, and its output is passed through.
  - **pre:** the chained hook gets the payload *after* keygent's rewrite (`'<launcher>' run --grant <id>`, trivially quotable). Its
    `updatedInput.command` is used only if it **equals a known wrapper template whose sole payload is the exact rewrite**, e.g.
    `/opt/homebrew/bin/lean-ctx -c ''<launcher>' run --grant 9f2c…'`. Anything else, such as `evil; '<launcher>' run --grant …`, is discarded,
    and keygent's rewrite wins. Wrapper templates are registered per chained tool by `integrate`. The decision is the **most restrictive** of the two (deny > ask > allow).
  - **post:** the chained hook gets the **redacted** payload. keygent's `updatedToolOutput` wins, and the chained `additionalContext` is passed through.
- `integrate lean-ctx` (and `integrate chain` for other tools) replaces those tools' entries for the same events with chained keygent
  entries, keeps a backup, and `--remove` restores them exactly. `doctor` warns about any unchained hook on `UserPromptSubmit`,
  `PreToolUse` (Bash/PowerShell) or `PostToolUse` that keygent doesn't know.

### 5.11 Web console (ADR 0005)

The broker launches `keygent-ui` after verifying its binary, and binds the origin to that child's lifetime. Passkey login uses a header token (not a cookie)
and gives a 15-min, metadata-only session. Each action needs its own assertion: approve/deny grants, policy and allow rules, trust/untrust, remove, rename,
seal. **No reveal and no value entry.** Approvals use `render_for_approval()`. Enrollment needs a passphrase proof. CSP is self-only, plus `no-store`
and Host/Origin checks. Under WSL, SSH and headless sessions it prints the URL instead of opening a browser.

### 5.12 Configuration

- `config/config.toml` (plain, user-editable) holds **UX-only settings**: default dialect, preferred approval channel order,
  notification on/off, log level, console auto-open. (Turning the generic detectors **off** is security-relaxing, so it lives in the index.)
- **Security settings** (TTL/idle above default, run-time caps above 30 min, `--remember` availability, default mode for new
  handles) live in the **encrypted index** and change only with auth.
- Precedence: CLI flag → config → default. `KEYGENT_*` env vars may only **tighten** security, never relax it.

### 5.13 Egress proxy (Phase 6, the T3 fix)

A per-run local HTTP(S) proxy owned by the broker. The child gets a dummy credential, and the proxy injects the real one only for the handle's `hosts`.

### 5.14 Adapters and backends

`AgentAdapter` / `SecretBackend` traits. v1: `claude` + `local`. Stubs: codex, cursor, gemini, opencode. External backends come in Phase 7.

---

## 6. Policy (ADR 0007)

### 6.1 Modes (encrypted index, changed only with auth)

| Mode | Meaning | Tier |
|---|---|---|
| `allow` | Silent **only** when an allow rule matches. Anything else falls through to `approve` | T2 |
| `approve` *(default)* | Every use needs a broker-verified approval of the exact command and scripts | T2 |
| `confirm` | Claude Code's dialog. Treated as `approve` in bypass/auto/dontAsk modes | T1 |
| `deny` | Never injected | — |

### 6.2 Allow rules

```toml
[[allow]]
exe    = "/opt/homebrew/bin/stripe"     # absolute, pinned when approved
# flags are structured: { name, takes_value }; a value is exactly ONE following argument that does not start with "-"
# (so "--limit --endpoint-url evil" never matches); "--flag=value" is accepted only for takes_value flags
sha256 = "…"                            # mismatch → approve, with "re-pin" showing old vs new hash, size and mtime (the binary is never executed to describe it)
args   = ["customers", "list", "*"]     # "*" = exactly one argument that does NOT start with "-"
flags  = [{ name = "--limit", takes_value = true }, { name = "--starting-after", takes_value = true }]  # required with "**"
home   = "scratch"                      # optional: run with an empty temp HOME and XDG dirs, so agent-edited dotfiles can't redirect the tool
```

- Allow rules are **env-only**: commands with placeholders, shell metacharacters, globs, `~` or `$` are never eligible (§5.7).
- **Config-file steering (T2 residual):** a pinned tool still reads config the agent can edit (`~/.aws/config` `endpoint_url`, `.npmrc`,
  kubeconfig `server:`, proxy settings in dotfiles), so a silent run could send the key elsewhere. Mitigations: `home = "scratch"` for tools
  that work without dotfiles. Rule creation warns that tools with endpoint/proxy configuration should stay in `approve`. Leak case included.

- `**` (the rest of the arguments) needs a `flags` allowlist. `--flag=value`, short-flag clusters and unknown or abbreviated flags don't match.
- Never wildcard-allowable: shells, interpreters and generic transfer tools (`sh`, `bash`, `zsh`, `pwsh`, `cmd`, `python*`,
  `node`, `deno`, `bun`, `ruby`, `perl`, `php`, `env`, `xargs`, `curl`, `wget`, `nc`, `ssh`, `scp`, `rsync`, `git`, `make`, `npm`, `npx`, …).
- Compound commands and PowerShell never match rules in v1.

### 6.3 Denylist (T1, bypassable)

`env`, `printenv`, `set`, `export -p`, `declare -x|-p`, `compgen -e`, `ps e…`/`ps -E`, `Get-ChildItem env:`, `dir env:`,
`/proc/*/environ`, echo/printf/`Write-Output` of secret vars, reads of the vault, runtime dir and `.env*`, `keygent reveal`.

### 6.4 Exposure

A handle is `exposed` after a `!!` override that matched a vault value, a PostToolUse redaction hit, or `exposed --mark`. Each run using it
prints one line telling the human to rotate it at the provider and then run `keygent rotate`.

---

## 7. Agent integration

`integrate claude`: idempotent, writes only entries it owns, backs up first, and `--remove` reverses exactly that. User scope by default; `--project` uses
`.claude/settings.local.json`. It installs the hooks (§5.10), the `permissions.deny` backstop, the skill, and records the shell paths (with auth).
**Skill** (`keygent`):
- Description (≤ 25 words): "Use secrets via keygent handles. Never ask for or paste secret values; reference `{{keygent:<handle>}}` and let keygent inject and redact them."
- Body (≤ 120 words): run `keygent ls` to list handles; use `{{keygent:<handle>}}` in commands; the first use asks the human to approve, so wait;
  if sealed, ask the user to run `keygent unseal`; never print env or read `.env`; if a value is needed in a file, ask the user to use a file binding.

`doctor` detects managed or enterprise Claude Code settings that disable user hooks, and reports that integration is ineffective.

## 8. lean-ctx

Composition is fixed by ADR 0002 and uses the chain composer (§5.10.2). keygent is innermost (`lean-ctx -c '… keygent run …'`) and runs first in every hook.
lean-ctx's own redaction stays on as a third layer.

## 9. Audit log

JSONL, owner-only. Each record has ts (wall clock) + seq, event, handles, decision, channel, rendered command template (never values), script
hashes, exit code and redaction count. The HMAC chain (`K_audit`) is anchored **after every record** in an append-only
`audit.anchor` file (`seq ‖ HMAC(K_audit, seq ‖ mac)`). On every vault write it is also anchored in the index, and every 10 min in the
keystore tripwire. Truncation is detected unless the log, the anchor and the tripwire are all rolled back together (same-user, documented).
`audit [--since] [--verify]`. Rotation at 10 MB × 5 with the chain carried over. An append failure means **fail closed** for runs.

## 10. Threat model

[THREATS.md](THREATS.md). Each row has a test. T3 gaps are listed.

## 11. Testing and quality gates

- **Unit:** crypto, AAD, tampering, oversized params, rollback tripwire, DEK rotation, recovery slot, estimator vectors, renderer escaping (bidi, zero-width, ANSI).
- **Property:** redactor chunking, tokenizers vs `sh`/`pwsh`, grammars, collisions, grant-key stability.
- **Integration (3 OSes):** never-plaintext, squat, exclusive bind + stale-socket recovery, mutual auth, auth flood (a human is never delayed), approvals
  (all channels), script hash re-check, PATH/cwd spoofing, pin mismatch, containment, crash sweep, sleep/clock-change sealing, disk full,
  audit failure, corrupt entry isolation, migrations, chain composer with a fake observer hook.
- **Leak suite:** 60+ cases tagged T1/T2/T3 (tests/leak/README.md). There are **two documented exceptions** to "canary never under `~/.claude`":
  (1) a secret the *human* pastes into a prompt, which may appear in local history; (2) a **PostToolUse** hit (e.g. a file written by a child
  and then read), because `updatedToolOutput` changes only what the model sees, so the transcript may keep the original. In both cases the test asserts
  that the value never reached the model (where applicable) and that the handle was **marked exposed**.
- **Plaintext boundary gate:** `preflight.sh` fails if `hook/`, `adapter/`, `policy/`, `proto/` or `ui/` reference `Secret`/`Dek`/`Subkey` (§4.2).
- **Test isolation:** the runtime ignores `HOME`/`XDG_*`/`TMPDIR` by design, so tests use a **`test-profile` cargo feature** that adds a
  `KEYGENT_TEST_ROOT` override for every location (data, config, state, runtime, keystore → file). The feature is **excluded from release
  builds**, and the release workflow checks that the shipped binary doesn't contain the override string. Without the feature, no env var can
  redirect any path.
- **Advisory monitoring between releases:** CI runs only on release (owner decision), so `cargo deny check advisories` runs in `preflight.sh`.
  A scheduled weekly advisory workflow (`.github/workflows/security.yml`, Mondays, read-only plus `issues: write` to open one alert issue) **was added by owner decision**.
- **Development testing on 3 OSes:** CI runs only when the owner starts it (owner decision), so day-to-day cross-OS testing uses local VMs
  (UTM/Parallels for Windows and Linux on macOS). `release.yml` is `workflow_dispatch` only: `snapshot` mode checks and builds any
  branch without publishing ([ADR 0017](adr/0017-release-pipeline-and-updates.md)).
- **Fuzz:** redactor, TLV, hook JSON, TOML, HTTP, CBOR, clientDataJSON, renderer.
- **Golden:** hook JSON (ADR 0001), ERRORS.md messages.
- **Gates:** `scripts/preflight.sh`. Release workflow (checks, cargo-deny, size and test-hook check per target, SBOM, signing, attestation; ADR 0017). Hook latency and RSS checked before release.

## 12. Operations (ADR 0008)

- **Install channels:** `install.sh` / `install.ps1`: download, verify SHA256 against `SHA256SUMS`, then verify the cosign bundle.
  **If `cosign` is missing the script stops** unless the user passes `--insecure-skip-signature` (checksum only, with a loud warning). Windows
  uses `cosign.exe`, and after GA also `Get-AuthenticodeSignature`. Releases also ship an SBOM (`cargo-cyclonedx`). The owner should enable tag
  protection for `v*`. The expected identity is pinned, the same string everywhere (README included):
  `--certificate-identity-regexp '^https://github\.com/DiyRex/keygent/\.github/workflows/release\.yml@refs/tags/v'`
  `--certificate-oidc-issuer https://token.actions.githubusercontent.com`, with the regex anchored to semver tags
  (`…@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$`). The bundle's workflow claims (`--certificate-github-workflow-repository`, `…-ref`) are also checked.
  Installers **refuse downgrades** unless `--allow-downgrade` is passed. The bootstrap script itself is trust-on-first-use (fetched over HTTPS from
  the repo); this is documented, and the signed-binary path is the verifiable one. Without cosign the scripts print how to verify manually. Then install to
  the user dir. The PowerShell script asks before adding to the user PATH. Also a Homebrew tap (`brew install diyrex/tap/keygent`, macOS/Linux,
  a formula rendered from the signed `SHA256SUMS`; ADR 0017) and `cargo install --locked` (on Linux with `--target <arch>-unknown-linux-musl`; a glibc build
  loses the `LD_PRELOAD` defence and exceeds the RSS budget, PLATFORMS)
  from source. winget/scoop come later. **Minimum Claude Code: 2.1.295** (`onFailure`). `integrate` and `doctor` refuse older versions.
- **Upgrade:** replace the binary (`brew upgrade keygent`), then `keygent seal && keygent unseal`. keygent never updates itself (ADR 0017). Hooks call the stable launcher, so paths survive upgrades. `doctor` repairs
  stale hook paths.
- **Uninstall:** seal → stop the broker and console → `integrate --remove` for every integration → remove the skill, runtime dir, config, broker log and
  keystore tripwire → remove the binary (on Windows, delayed deletion if it is locked). **Kept unless `--purge`:** the vault, `vault.kgt.prev` and the audit log.
- **`doctor`:** numbered checks with pass/warn/fail. Binary path + signature; version vs broker; vault location (not on network/sync FS); permissions;
  endpoint; hook entries present, paths valid and live self-test; unchained observer hooks; managed settings; `permissions.deny`;
  memory-lock limits; disk encryption on (FileVault/BitLocker/LUKS — recommended, because hibernation images and swap hold memory);
  per-OS protection level. `--report` produces a paste-safe bundle (versions, paths, check results, no handles, no commands).
- **Supported environments:** see PLATFORMS.md §Environments. Summary: macOS, Windows and Linux desktops are fully supported. WSL2 counts as Linux (no native prompt;
  console URL printed). SSH/headless works with `keygent approve` from a second terminal. Containers get one vault per container,
  and socket mounting is unsupported. **CI is unsupported in v1** (no passphrase env var by design).
- **Errors and exit codes:** [ERRORS.md](ERRORS.md). The child's code passes through; keygent uses 64 (usage), 74 (run killed by runtime or
  output cap), 75 (approval denied or timed out), 76 (manifest not trusted), 77 (policy deny), 78 (sealed), 79 (broker or version error). The `keygent:` line tells keygent errors apart from
  a child that happens to use the same code.
- **License:** **Apache-2.0** (owner decision, matching lean-ctx). `LICENSE` + `NOTICE` ship in every release archive. Release artifacts include third-party notices (`cargo-about`).

## 13. Phases (Linux + macOS + Windows from Phase 1)

| Phase | Scope |
|---|---|
| **0 — Spikes & design** | Done: design, hook contract (ADR 0001, *verify* items remain), lean-ctx (ADR 0002). Remaining: platform spike, native prompts from the background, WebAuthn on localhost, dependency sizes |
| **1 — Vault core** | Platform skeleton, format v1, passphrase + recovery slots, init/passwd/rekey/recover/verify/backup/restore, secrets CRUD + rename + rotate undo, estimator, limits, migrations framework |
| **2 — Broker + run** | Unseal handoff, hardening, endpoint + stale recovery, protocol, mutual auth + rate limits, tokenizers, allow rules, grants + script binding + renderer + `approve`, containment + crash sweep, run limits, redactor, trust, capture, audit, timers, logging, leak harness |
| **3 — Claude Code** | Hooks per ADR 0001, chain composer, native prompts, policy modes, `integrate`/`uninstall`, skill, `doctor`, ERRORS golden tests, full T1/T2 leak suite |
| **4 — Web console** | Broker-launched UI, passkeys, approvals, management |
| **5 — lean-ctx + distribution** | `integrate lean-ctx`, install scripts, Homebrew tap, signed releases |
| **6 — Hardening** | Egress proxy, screen-lock seal, passkey PRF unseal, user-presence slots, Shamir, MCP |
| **7 — Ecosystem** | Other adapters, external backends |

## 14. Definition of done (v1 = Phases 0–5)

- On macOS, Windows (Git Bash + PowerShell) and Linux: `install → init (recovery key confirmed) → add → integrate claude → unseal`.
  Then "list my Stripe customers using {{keygent:stripe/live}}" asks for approval once and works, and the canary appears nowhere in the transcript, the lean-ctx archive
  or the logs.
- All T1/T2 leak cases pass on every OS, **except the cases tagged `known-gap`**, which must produce exactly the documented behavior
  (THREATS "Known gaps": env read during a run, unbound/transitive code, config steering, the `Redact` oracle). T3 cases are documented. Budgets are met. Fuzzers, clippy and cargo-deny are green. Releases signed via cosign + provenance and verified by the install scripts (macOS notarization and Windows Authenticode deferred by owner decision). License: Apache-2.0.
- README, THREATS, SECURITY, PLATFORMS, ERRORS, ADRs and diagrams match the shipped behavior.

## 15. Open items (verification only)

| Item | Fallback |
|---|---|
| `if` filter pattern for `onFailure: block` on placeholder commands | Use `onFailure: continue` for Bash/PowerShell (the broker still enforces) |
| Claude Code sandbox setting names for filesystem deny-read (to lift the read rules from T1 to T2) | Read rules stay T1. The device pepper still protects a copied vault |
| Keychain ACL / DPAPI / Secret Service storage of the device pepper without prompts on every unseal | Store the pepper in an owner-only file (weaker: equals a T2 copy). `doctor` says so |
| `updatedToolOutput` schemas per built-in tool, per Claude Code version | Golden tests. An unknown tool → block + exposed |
| Native UV prompt from a windowless broker | Helper process spawned by the broker, or `keygent approve` only |
| WebAuthn on `http://localhost` | `https://localhost` with a pinned per-install cert |
| Memory-lock limits | Smaller arena. `doctor` guidance |
| OWNER RIGHTS ACE effectiveness | Document as T3 |

## 16. Glossary

**Broker:** the unsealed daemon, the only process holding plaintext. **Grant:** a pending authorization to run one exact command.
**Grant key:** the hash binding a grant to command, cwd, handles, program and script contents. **Pin:** an allow rule's absolute path + SHA-256.
**Auth:** a mutual passphrase proof, or broker-raised OS user verification. **Exposed:** a handle whose value may have left the
broker unredacted. **Chain composer:** keygent wrapping another tool's hook so that keygent always runs first.

## 17. Revision log

- **v1 → v2 (security review, 18 items):** broker-spawned children; hooks as UX; re-auth instead of TTY; trusted manifests;
  tokenized rules; allowlist over denylist; broker grants; create-only capture; protected redactor heap; UUID/HKDF/header MAC; 0700
  dir; audit anchor; no plain-keystore unseal; tokenizer placeholders; Phase-0 threat model; `--delete`; "broker" rename; release-only CI.
- **v2 → v3 (14 items):** passkey console; Windows in v1; spawn + inherited pipe; mutual auth; auth limits; cross-OS memory protection;
  containment; canonical paths; injection defenses; concealed clipboard; PowerShell; UTF-16LE; device safety; console moved earlier.
- **v3 → v4 (adversarial review, 18 items):** broker-observed approvals (critical); pinned allow rules; broker-launched console without
  reveal or value entry; fixed endpoint paths; oracle limits; DEK-rotating rekey + tripwire; OWNER RIGHTS + handle list; macOS
  best-effort containment; no auto-seal; full crypto spec; trust diff + reserved env names; `add` needs auth; PowerShell
  approve-only; clipboard reveal; no `NO_NEW_PRIVS`; lighter allocator; renumbered phases; limits.

**v4 → v5 (verified hook contract, lean-ctx test, second independent review):**

| # | Gap | v5 resolution |
|---|---|---|
| 51 | Approving `bash ./run.sh` approved the text, not the script | Script binding: hashes in the grant key, re-checked before exec, shown in `approve` (§5.5.2) |
| 52 | Approval display spoofable (bidi, ANSI, newlines, length); native prompts truncate | `render_for_approval()`, escaping, native prompt only for short plain commands (§5.5.2) |
| 53 | Global auth delay let the agent stall the human | Per-connection delay, a correct proof is never delayed, reserved connections, pending cap (§4.1) |
| 54 | Hooks run in parallel, so other observers (lean-ctx) saw raw prompts and outputs first | Chain composer: keygent always runs first (§3.2.9, §5.10.2, ADR 0002) |
| 55 | Blocked prompts are kept in the transcript by default | `suppressOriginalPrompt: true` (*verify*) (§5.10.1) |
| 56 | `updatedInput` replaces the whole tool input | Rewrite keeps all original fields (§5.10.1) |
| 57 | `confirm` under bypass/auto modes | Treated as `approve` when `permission_mode` is permissive (§5.10.1) |
| 58 | Default hook timeout 600 s | `timeout: 5` (§4.1) |
| 59 | No recovery for a lost passphrase; no passphrase change | Recovery-key slot, `passwd`, `recover`, `verify` (§5.2) |
| 60 | Timers ignored suspend and clock steps | Dual deadlines, seal on wake after a long suspend (§4.1) |
| 61 | No environment matrix (WSL/SSH/containers/CI/RDP); broker scope contradiction | PLATFORMS §Environments, per-user (Unix) / per-session (Windows) scope (§5.4, §12) |
| 62 | Lost updates with concurrent writers; network filesystems | Read-modify-write under lock, mutations via the broker while unsealed, network/sync FS refused (§5.2) |
| 63 | Upgrade, migration and machine move undefined | Version-mismatch behavior, stable launcher path, format migrations, `restore --new-machine` (§5.2, §5.4, §12) |
| 64 | Crash, corruption, disk-full and stale-socket handling undefined | `.prev`, per-entry isolation, `verify`, lock-file stale detection, crash sweep, PDEATHSIG, fail closed on audit failure (§5.2, §5.4, §5.7) |
| 65 | No configuration model | UX-only `config.toml`, security settings in the index, env may only tighten (§5.12) |
| 66 | PTY, runtime and output caps, `\r` flushing, rotate coverage | Pipes only, `TERM=dumb`, 30 min / 10 MiB caps, `\r` flush, old value kept in the redactor (§5.7) |
| 67 | Ambiguous exit codes, no error catalog | 64/75/76/77/78/79 + ERRORS.md (§12) |
| 68 | No logging or support story | `broker.log` (no values), `version`, `doctor` checklist + `--report` (§5.4, §12) |
| 69 | Undefined estimator, agent markers, build id, dialect selection; `deny_flags` was a denylist | Deterministic estimator, `CLAUDECODE=1`, build id, dialect rules, `flags` allowlist (§5.3, §5.7, §6.2) |
| 70 | Install channels, Windows PATH vs device safety, uninstall details | §3.3 exception, install scripts, Homebrew, uninstall sequence (§12) |
| 71 | `rename`, `rotate --undo`, `import` conflicts missing | Added (§5.1, §5.2) |
| 72 | Multi-agent approval UX | Id required with several pending, FIFO native prompts, notification, remember keyed by grant key (§5.5.2) |
| 73 | Skill text and doctor checks unspecified | Written out (§7, §12) |
| 74 | License TBD | **Resolved:** Apache-2.0 (§12) |

**v5 → v6 (full hook-doc verification + implementability pass):**

| # | Gap | v6 resolution |
|---|---|---|
| 75 | Assumed `suppressOriginalPrompt` kept pasted secrets out of the transcript. Verified: it only changes the block message, so the text may still be stored in local transcript and history | Honest non-goal (§2.1). Vault matches always mark the handle exposed. Block message says "rotate it". Leak-suite exception documented (§5.10.1, §11) |
| 76 | A mismatched `updatedToolOutput` is silently ignored, so the original output is sent (fail-open) | Exact per-tool schemas + golden tests. Unknown tools → block + exposed. `doctor` live self-test (§5.10.1) |
| 77 | The agent could read its own transcript/history files, which may hold raw prompts or outputs | Read deny for `~/.claude/projects/**` and `~/.claude/history.jsonl` (§5.10.1) |
| 78 | Hooks failed open even where failing closed is cheap | `onFailure: block` for prompts and for placeholder commands (§5.10.1) |
| 79 | No concrete data formats | FORMATS.md: vault binary layout, index schema, manifest, config, audit record, hook JSON |
| 80 | No module boundary for plaintext | §4.2 module table, `pub(crate)` secret types, preflight import gate |
| 81 | Native prompt implementation unspecified. WinRT would add a heavy dependency | macOS LAContext via objc2. Windows Hello via the NCrypt Passport KSP (Win32, cryptographic proof) (§4.3) |
| 82 | No way to add multi-line or file secrets (PEM, service-account JSON) | `add --multiline`, `--from-file [--delete]` (§5.1) |
| 83 | The 30-min cap killed dev servers and watchers | `--max-runtime` up to 4 h, shown in the approval and part of the grant key (§4.1) |
| 84 | Scope was implicit | Explicit non-goals (§2.1) |
| 85 | Chained hooks broke the latency budget | Budget excludes chained hooks, which are reported separately (§4.1) |
| 86 | Cross-OS dev testing undefined given release-only CI | Local VMs. Optional `workflow_dispatch` pending owner approval (§11) |

**v6 loop round 1 (independent review: critical 1, high 9, medium 10, low 2 — all accepted):**

| # | Finding | Resolution |
|---|---|---|
| 87 | **Critical:** script approval showed 40 lines, cwd chosen by the agent, transitive code unbound | Full script mandatory (page to end), 16 KiB cap, project-root cwd rule, explicit "not bound" label, no `--remember` (§3.2.4, §5.5.2) |
| 88 | Slot AAD covered `generation`, so the broker couldn't write the vault | Slot AAD excludes generation. `header_mac` covers it (§5.2, FORMATS) |
| 89 | Allow-rule "no shell" path vs `"$KEYGENT_X"` placeholders → argv leak | Allow rules env-only. Placeholders/metacharacters ineligible. `*` never matches `-…` (§5.7, §6.2) |
| 90 | Pinned tools can be steered by agent-edited config files | T2 residual documented. `home = "scratch"`. Warning at rule creation (§6.2) |
| 91 | File-read controls overclaimed at T2 (Bash bypasses them) | Labeled T1. T2 only with Claude Code's sandbox deny-read. Device pepper against a copied vault (§5.2, §5.10.1) |
| 92 | Naive estimator passed `Passw0rd!2024`; `Redact` oracle | Pattern-aware estimator + common list, generated passphrase by default, 80-bit secret floor, per-connection `Redact` limits (§4.1, §5.3) |
| 93 | Rewritten command re-parsed by the outer shell or wrapper | `keygent run --grant <id>` with no command text. The broker runs the stored command (§5.5.2, §5.7, §5.10) |
| 94 | UV auth had no protocol path. `trust` content shown only to the agent | `UvAuth` limited to short broker-rendered actions. Trust/edit content shown in the human's CLI and hash-bound (§5.5.1) |
| 95 | `.prev`/`.pre-vN` kept old factors and values after passwd/rekey/rm/rotate | Deleted once the new file is durable. Backup warning (§5.2) |
| 96 | Prompt hook with a sealed/down broker undefined; `onFailure` version | Local generic detectors, reserved connection, chunking, min Claude Code 2.1.295 (§5.10.1, §12) |
| 97 | Only the first program bound; shells loaded rc/profile | Every executable hashed and re-checked. No-rc/no-profile shells (§5.5.2, §5.7) |
| 98 | Grant flood expired the real grant before display | Timer starts at display, per-(PID, cwd) quota, `deny --all`, pending banner (§4.1, §5.5.2) |
| 99 | `approve` semantics inconsistent; grant use count unstated | Approve binds the grant-key hash into the proof. Single-use (§5.5.2) |
| 100 | Client disconnect left the child running; caps' exit code | Kill on disconnect. `run_in_background` for long runs. Exit 74 (§5.7, ERRORS) |
| 101 | Multi-line secrets leaked line by line | Per-line and re-wrapped patterns (§5.8) |
| 102 | Same-user env read misclassified as T3 | Reclassified as a known **T2** gap, with mitigations (§2.1, THREATS) |
| 103 | `rekey` couldn't keep the recovery slot | New recovery key at rekey. Checksum group (§5.2) |
| 104 | Reveal auth inconsistent across docs | Passphrase-only everywhere (§5.1, §5.5.1) |
| 105 | Re-pin ran `--version` of an unapproved binary | Hash, size and mtime only (§6.2) |
| 106 | Audit anchor cadence unclear | Per-record anchor file + index + tripwire (§9) |
| 107 | Recorded Linux paths agent-steerable; `bindat` doesn't exist | Fixed home-derived paths, XDG ignored at runtime; `/proc/self/fd` bind trick (PLATFORMS) |
| 108 | Cross-reference drift (`deny_flags`, phase numbers, §14 vs §15, AGENTS, headers, README) | Aligned across all docs |
| 109 | Installer verification unspecified; KDF cap DoS; challenge encoding | Pinned cosign identity, m ≤ 256 MiB, length-prefixed challenge encoding (§5.2, §12, ADR 0004/0005) |

**v6 loop round 2 (independent review: critical 2, high 6, medium 14, low 2 — all accepted):**

| # | Finding | Resolution |
|---|---|---|
| 110 | **Critical:** project-code label was denylist-shaped (wrappers, inline code, PowerShell unlabeled) | Inverted: "bound" only if every word is a leaf tool. Everything else unbound + warning + no remember (§5.5.2) |
| 111 | **Critical:** config steering also hits approved runs (`~/.curlrc` proxy) | Per-tool config-file hashes, "changed since last approval" warning, `home = "scratch"` for any run (§5.5.2) |
| 112 | Windows Hello text is per-key, not per-request | Phase 0 pass/fail. Otherwise no native channel on Windows (§4.3, §5.5.1) |
| 113 | Hooks and `run` couldn't detect a fake broker | All clients verify the server PID, its binary and the lock holder. Fail closed (§5.4) |
| 114 | Idle flush emitted partial secret prefixes | Hold-back rule (§5.7) |
| 115 | DoD impossible given known T2 gaps; stale T3 labels | `known-gap` tag and DoD exception; labels fixed (§14, PLATFORMS, ADR 0003/0006) |
| 116 | SECURITY.md reveal/slot-AAD drift | Fixed |
| 117 | Script hash-then-exec race; shebang interpreter unbound | Execute the hashed bytes. Bind the shebang interpreter (§5.5.2) |
| 118 | Pepper overclaimed on Linux/Windows; no-keystore and lost-pepper paths undefined | Honest scope, file fallback, recover path (§5.2) |
| 119 | Factor changes with live brokers; audit chain across rekey | Seal all brokers first, `header_mac` re-check on reload, epoch record (§5.2) |
| 120 | Entry version/caps/MAC encoding unspecified | FORMATS: version equality, unlisted entries ignored, caps, exact MAC input |
| 121 | Tripwire only warned; `.prev` kept looser policy | Refuse unless confirmed. Purge `.prev` after tightening changes (§5.2) |
| 122 | Session nonce reuse across directions | Per-direction keys, counter regression rejected (ADR 0004) |
| 123 | `UvAuth` prompt fatigue on `rm` | `rm` passphrase-only. Requester shown. 1 UV prompt per 30 s (§5.5.1) |
| 124 | Approval wait vs Bash tool timeout; queue-full code | 90 s wait, tool timeout raised to ≥ 150 s, grant reuse, `RateLimited` 79 (§5.5.2) |
| 125 | Reserved-connection mismatch; quota keyed on hook PID | Reserved slots for any auth-carrying frame, aligned at 5. Quota keyed on (uid, session_id, cwd) (§4.1, ADR 0004) |
| 126 | Hashing large executables in the hook path | Hashing happens off the hook path, cached by (dev, inode, size, mtime, **ctime**). User-writable files are re-hashed on Windows (§5.5.2) |
| 127 | Estimator overrated letters-only text | 2 bits/char for non-dictionary letters. `--own-passphrase` ≥ 16 chars + 70 bits (§5.3) |
| 128 | Placeholder in quotes undefined; `.cmd`/`.bat`; capture env name | Quote-context table. `.cmd`/`.bat` refused. Reserved check on every `env_name`. `capture` uses the default name (§5.7, §5.9) |
| 129 | Installer silently skipped cosign; identity mismatch; README Windows snippet | Fail closed without cosign. One pinned identity. README aligned. SBOM, tag protection (§12, README) |
| 130 | README said XDG respected; two macOS endpoints | XDG ignored. macOS endpoint = confstr dir, `/tmp/keygent-<uid>` only if the path is too long (README, PLATFORMS) |
| 131 | Misc cross-reference drift | Reconciled (THREATS, ERRORS, AGENTS, ROADMAP, ADR 0004, README) |
| 132 | Passkey counter always 0 on synced passkeys; UP/UV flags | Counter checked only if non-zero. UP and UV flags required (ADR 0005) |

**v6 loop round 3 (independent review: critical 1, high 4, medium 15, low 3 — all accepted; one sub-claim about AGENTS.md platforms was already fixed):**

| # | Finding | Resolution |
|---|---|---|
| 133 | **Critical:** client stdin forwarded to approved children (`psql`, `kubectl apply -f -`) | stdin = `/dev/null` unless the stored command supplies it. No client stdin frame (§3.2.7, §5.7, ADR 0004) |
| 134 | `uninstall --purge`, `--remove`, `integrate chain` needed no auth | Passphrase. `--purge` also needs a typed confirmation. Bash self-edit of settings documented as a T2 gap (§5.1) |
| 135 | Leaf tools executing file inputs (`psql -f`, `kubectl apply -f`, `gh alias`) labeled bound | File inputs hashed, shown and executed from those bytes. A per-tool "executes embedded code" list makes them unbound (§5.5.2) |
| 136 | Placeholders expanded into argv (visible to other users) despite "never argv" | Argv placeholders refused by default. `{{keygent-file:…}}`. Per-handle `argv = "allow"` with a warning (§3.2.6, §5.7) |
| 137 | Windows native-prompt design contradicted across ADR 0007/PLATFORMS/DEPENDENCIES/ROADMAP | SPEC §4.3 canonical. Companion docs updated |
| 138 | Approval wait 120 vs 90 s; unbounded queue wait | 90 s from display, 5 min from creation. Example timeout fixed (§4.1, FORMATS) |
| 139 | Two different quota keys | One key (uid, cwd), evict oldest from the same cwd, availability-only (§4.1) |
| 140 | Reserved connections starvable via an unauthenticated `Hello` | 2 s to authenticate, 1 per peer PID, `control` limited (§4.1) |
| 141 | `flags` arity undefined (`--limit --endpoint-url evil`) | Structured `{name, takes_value}`, values never start with `-` (§6.2) |
| 142 | How the hook detects allow-rule commands undefined | `Check` round trip per Bash/PowerShell call while unsealed. Fails safe when sealed (§5.10.1) |
| 143 | PostToolUse can't keep the transcript clean | Second documented exception. Test asserts the exposed flag (§11) |
| 144 | Clipboard reveal readable by the agent | Default is the alternate screen with auto-clear. `--copy` opt-in. T2 gap documented (§5.1) |
| 145 | Lock-holder PID not portably discoverable; PID reuse | Lock file records pid + start time + exe. Client checks those plus lock-held (§5.4) |
| 146 | OS integration deps unlisted; musl `getpwuid`; no-D-Bus pepper | DEPENDENCIES/spike rows, `secret-tool` or file fallback, `$HOME` fallback with ownership check (§5.2, §5.4) |
| 147 | Index TLV unspecified; `Import` > frame; `MatchPrompt` chunk overlap | FORMATS TLV byte rules, per-entry `Import`, 64 KiB chunk overlap |
| 148 | KEK/subkey HKDF parameters unspecified; `passwd` salt | Exact derivations, per-slot salt, golden vectors (§5.2) |
| 149 | Queue-full exit code conflict | 79 `RateLimited` everywhere (ERRORS) |
| 150 | AGENTS.md layout drift | Layout points to SPEC §4.2 |
| 151 | `mlockall` failure mode; rlimits inherited by children | Degrade to arena-only + warning. Arena lock is mandatory. Pre-exec resets rlimits (§5.4) |
| 152 | Rollback tier inconsistency | T2 on Linux/Windows (THREATS) |
| 153 | `MarkExposed` spam | Rate-limited to 1/min per handle. Only notifies (ADR 0004) |
| 154 | Estimator step order; TERM, env-ref and macOS endpoint drift | Aligned (§5.3, PLATFORMS, ADR 0006) |
| 155 | Cosign regex too loose; downgrades; TOFU bootstrap | Semver-anchored regex, workflow claims checked, downgrade refused, TOFU documented (§12) |

**v6 loop round 4 — final round under the 4-round cap (independent review: critical 0, high 4, medium 10, low 6 — all accepted except #19, deferred to the owner):**

| # | Finding | Resolution |
|---|---|---|
| 156 | Leaf status per binary, not per subcommand (`doppler run --`, `kubectl exec`, `psql -c '\!'`) | Per-tool shipped grammars. Anything outside is unbound. Handoff after `--` is always unbound (§5.5.2) |
| 157 | First approval of a tool had no config baseline | Bound runs default to `home = "scratch"`. First approval lists all existing config files and needs terminal/console (§5.5.2) |
| 158 | `keygent` shim/alias capturing the passphrase misfiled as T3 | Reclassified as a T2 residual. Sandbox write-deny on the launcher and rc files, `doctor` fails without it, binary path and signature shown at every prompt (§5.5.2, THREATS) |
| 159 | Leak tests would touch the real vault (env overrides are ignored by design) | `test-profile` feature, excluded from release and checked in the release workflow (§11) |
| 160 | Bash tool timeout could kill a run after a slow approval | timeout = min(600 s, original + 90 s + 30 s) (§5.5.2) |
| 161 | Rewrite relied on PATH; user deny rules bypassed; loose chain check | Absolute launcher. Original command checked against user deny/ask rules. Wrapper templates (§5.10) |
| 162 | Fail-closed scope on broker verification; re-pin on upgrade | Same scope as the version lock. Signed builds pinned by identity, unsigned re-pinned at unseal (§5.4) |
| 163 | `verify`/`ls` auth while sealed | `verify` via the broker or with the passphrase. `ls` sealed → 78 (§5.1) |
| 164 | Pepper file location contradictory | State dir only, never the data dir, excluded from backups (§5.2) |
| 165 | Duplicate timing/quota values | §4.1 canonical. Duplicates removed (§5.5.2) |
| 166 | Project root forgeable | `CLAUDE_PROJECT_DIR` for hook grants. UX-only for direct runs (§5.5.2) |
| 167 | macOS `/tmp` fallback unchecked | `lstat` owner/mode/symlink checks on every fallback dir (§5.4) |
| 168 | `deny`/`untrust` auth contradictory | No auth for either. Removed from `UvAuth` (§5.5.1, ADR 0004) |
| 169 | Redactor size unbounded vs RSS/mlock | 8 MiB pattern cap, refusal message, per-line entropy gate (§5.8) |
| 170 | File bindings misfiled as T3 | T2 known gap, alongside env read (THREATS) |
| 171 | Slot size, THREATS AAD, ADR 0004 concatenation, `project_code_label` drift | Aligned (FORMATS, THREATS, ADR 0004) |
| 172 | Principle numbering and §5.7 limits | Renumbered 1–11, references fixed (§3.2, §5.7) |
| 173 | README regex, "remember as rule", argv caveat | Aligned (README, ADR 0007) |
| 174 | No advisory checks between releases | `cargo deny` in preflight. Scheduled workflow **deferred: owner decision** (§11) |
| 175 | `mcp` listed as v1 | Marked Phase 6 (§5.1) |
| 176 | Only a Mac available; 3-OS rule can't be met now | Windows verification deferred, compile-check only, no phase DONE until Windows runs ([ADR 0010](adr/0010-windows-verification-deferred.md)) |
| 177 | Owner wants a Homebrew tap, auto-updates, and no automatic CI | GoReleaser on one macOS runner, manual `release.yml` (snapshot/release), formula tap, updates via `brew upgrade`/`brew autoupdate`, no self-update; Windows release asset waits for the platform layer ([ADR 0017](adr/0017-release-pipeline-and-updates.md)) |
| 178 | Linux broker RSS 5.55 MiB on a glibc build (budget 5 MB) | Budget and injection defence apply to the static musl build that ships (2.61 MiB); source installs on Linux use the musl target (§12, PLATFORMS, README) |
| 179 | Agents run tools many times; per-command approval is impractical, and leases leave a T2 value leak | **Credential custody** for single-line values (default): the child gets a format-preserving dummy, a broker proxy adds the value only toward hosts the human approved (`edit --allow-host`); custody-only commands need no per-command approval. Non-HTTP secrets use `--no-custody` and approval ([ADR 0022](adr/0022-credential-custody-multi-cloud.md)) |
