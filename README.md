<h1 align="center">keygent</h1>

<p align="center">
  <b>Let AI coding agents use your secrets without ever seeing them.</b><br>
  A tiny local secrets broker for Claude Code and other agents: one static binary, no daemon to babysit, no cloud.
</p>

<p align="center">
  <img alt="status" src="https://img.shields.io/badge/status-pre--alpha-orange">
  <img alt="platforms" src="https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux-blue">
  <img alt="language" src="https://img.shields.io/badge/built%20with-Rust-dea584">
  <img alt="size" src="https://img.shields.io/badge/binary-%E2%89%A42%20MB-green">
  <img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue">
</p>

> **Status:** keygent is under active development and not ready for use yet. This README describes the v1 behavior.
> Commands and flags may change before the first release.

---

## The problem

Today, giving an agent a credential means pasting it into the chat or letting it read your `.env`. Either way the
secret ends up in the model's context. It gets sent to the provider, saved in transcripts and session logs, and can be
echoed back in any later tool output.

## The idea

The agent works with **handles** like `stripe/live`, never with values.

```text
You:    "List my Stripe customers using {{keygent:stripe/live}}"
Agent:  STRIPE_API_KEY={{keygent:stripe/live}} stripe customers list --limit 3
keygent:  ↳ Touch ID prompt: "Allow stripe customers list to use stripe/live?"   ← you approve
        ↳ runs it with the value injected into that one process only
        ↳ output streamed through the redactor
Agent sees: {"data":[…], "api_key": "‹keygent:stripe/live›"}
```

The value only ever exists inside keygent's local broker and the one process you approved. Anything that process
prints is redacted before the agent reads it.

## Features

- 🔐 **Encrypted local vault.** XChaCha20-Poly1305 per entry, Argon2id key derivation, envelope encryption.
  Uses audited RustCrypto crates only.
- 🧷 **Handles, not values.** Use `{{keygent:<handle>}}` in commands, or map handles to env vars once per project.
- 🚫 **Never in argv (by default).** Secrets reach a command as an environment variable or a private file, never as an argument, so other users can't see them in `ps` or `/proc/*/cmdline`. You can allow argument use for a specific secret if you accept that.
- 🧹 **Streaming redactor.** Catches raw, base64 (std/url, every alignment), hex, percent-encoded and JSON-escaped
  forms, including matches split across output chunks. Also flags unknown key-shaped tokens (AWS, GitHub,
  Stripe, JWT, PEM).
- 🛡️ **Guardrails.** Blocks `env`/`printenv` dumps, reads of `.env` or the vault, pasted secrets in prompts, and
  secret values written into source files.
- ✋ **Approvals the agent can't fake.** By default, every use of a secret needs your OK through Touch ID (macOS),
  your passkey, or `keygent approve` in your own terminal. keygent checks the approval itself, so an agent can't click
  through it or forge it.
- 📌 **Pinned allow rules.** Make trusted tools silent: a rule pins the exact program (path and fingerprint) and its
  arguments. A look-alike binary, a changed `PATH`, or extra flags don't match.
- 🤝 **Trusted manifests.** Project secret mappings take effect only after you run `keygent trust` and review the file. If the agent
  edits it, access stops until you trust it again.
- 🔑 **Your passphrase guards changes.** Adding, revealing, rotating, deleting and changing policy all ask for it. It is
  never sent anywhere, not even to keygent's own broker.
- 🔒 **Seal/unseal.** Works like `ssh-agent`: unseal once per session; it auto-seals on TTL, idle timeout or command. A small
  local broker is the only process that ever holds values, in locked memory that is wiped on exit.
- 🧾 **Tamper-evident audit log.** Records which handles were used, by which command, and the result. It never records values.
- 🪶 **Small and fast.** Single static binary ≤ 2 MB, ≤ 5 MB RAM when idle, hooks under 30 ms, zero agent tokens on the
  happy path.
- 🤝 **Works with lean-ctx.** Detects it automatically and composes with it, redacting before anything is compressed or cached.
- 💻 **macOS, Windows and Linux.** Same guarantees on each, built on each OS's native protections: named pipes and Job Objects
  on Windows, the hardened runtime on macOS, and subreaper and locked memory on Linux. Works with bash, Git Bash and PowerShell.

### Safe for your machine

keygent never needs admin or root rights. It installs no services, drivers or startup items, and never edits your shell
config. It only listens on `localhost` (for the optional web console), and only while you use it. It makes no network
connections and sends no telemetry. Commands it runs are contained, so nothing they start keeps running after they finish.
`keygent uninstall` removes everything it added (it asks for your passphrase). Add `--purge` to delete the vault too (you'll be asked to type a confirmation).

---

## Install

One line, no admin rights (available from the first release on):

```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/DiyRex/keygent/main/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/DiyRex/keygent/main/install.ps1 | iex
```

The installer:

1. Picks the right build for your system (macOS Apple Silicon/Intel, Linux x86_64/arm64, Windows x64/ARM64).
2. **Verifies the download's Sigstore signature.** It must come from this repository's release workflow and a `vX.Y.Z` tag. If you don't
   have `cosign`, the installer fetches a pinned copy into a temp folder and checks that copy's own fingerprint first.
3. **Verifies the SHA-256 checksum** against the signed checksum list.
4. Refuses to downgrade without `--allow-downgrade` / `-AllowDowngrade`.
5. Installs to `~/.local/bin/keygent` (macOS/Linux) or `%LOCALAPPDATA%\Programs\keygent\keygent.exe` (Windows). It never needs `sudo`,
   never edits your shell profile, and adds itself to the Windows user PATH only if you agree.

If any check fails, nothing is installed. Options: `--version vX.Y.Z`, `--prefix <dir>` (sh) / `-Version`, `-AddToPath` (PowerShell).
To pass options through a pipe: `curl -fsSL …/install.sh | sh -s -- --version v0.1.0`.

Prefer to read the script first? Download `install.sh` / `install.ps1`, look through it, then run it. Release archives,
`SHA256SUMS`, its Sigstore bundle and build-provenance attestations are also on every
[GitHub release](https://github.com/DiyRex/keygent/releases) for manual verification. (macOS notarization and Windows Authenticode
signing aren't set up yet. Downloads made by the installer aren't quarantined, so Gatekeeper doesn't block them.)

**From source** (requires Rust stable):

```sh
git clone https://github.com/DiyRex/keygent.git && cd keygent
cargo build --release --locked
mkdir -p ~/.local/bin
install -m 0755 target/release/keygent ~/.local/bin/keygent      # Windows: copy target\release\keygent.exe onto your PATH
```

Until the first release, keygent is **pre-alpha**: commands that aren't built yet are rejected as unknown (exit `64`).
The commands below start working as each phase in [`docs/ROADMAP.md`](docs/ROADMAP.md) is merged. If your shell says
`command not found` right after installing, run `hash -r` or open a new terminal.

## Quickstart (60 seconds)

```sh
keygent init                    # create your vault, choose a passphrase, save the recovery key it shows you
keygent add stripe/live         # paste the value here, in YOUR terminal (never in the chat)
keygent integrate claude        # install the Claude Code hooks + skill
keygent unseal                  # unlock for this session (default TTL 8h)
```

Now, in Claude Code:

> *"List my Stripe customers using {{keygent:stripe/live}}"*

The first time, you approve the exact command with Touch ID (macOS), your passkey in the console, or `keygent approve`. The
agent gets the results, and the key never appears in the transcript. To make a trusted tool silent, add an **allow rule** for it
(`keygent edit stripe/live`, or "approve and add as rule" in the console). `--remember` only skips prompts for the identical command for 15 minutes.

---

## Usage guide

### 1. Manage the vault

```sh
keygent init                    # create the vault (owner-only, see Files below)
keygent unseal [--ttl 8h]       # unlock: starts the local broker that holds keys in locked memory
keygent status                  # sealed/unsealed, time left, number of handles
keygent seal                    # lock now: key wiped from memory
keygent passwd                  # change your passphrase
keygent rekey                   # new encryption key for everything (after a suspected leak)
keygent recover                 # forgot your passphrase? use the recovery key from init
keygent verify                  # check the vault for damage; offers the last good copy
keygent backup <file>           # encrypted backup
keygent restore <file> [--new-machine]
```

`keygent init` shows a **recovery key** once and asks you to type it back. Store it offline (a password manager or paper).
Without the passphrase or the recovery key, your secrets cannot be recovered by anyone. By default `init` gives you a strong
six-word passphrase. Use `--own-passphrase` to pick your own (at least 16 characters, and common or guessable ones are refused).
The vault is also tied to this device, so a copied vault file can't be cracked on another machine. To move machines, use `restore --new-machine` with your recovery key.

While the vault is sealed, any command that needs a secret stops with:

```text
keygent: vault sealed — ask the user to run 'keygent unseal'
```

### 2. Add and manage secrets (you, not the agent)

You type values in your own terminal, and every change asks for your passphrase.

```sh
keygent add stripe/live --env STRIPE_API_KEY --desc "Stripe live key"
keygent add gcp/sa --from-file ./sa.json --delete   # multi-line / file secrets (PEM keys, JSON credentials); --multiline to paste
keygent edit stripe/live        # change metadata or policy
keygent rotate stripe/live      # replace the value, keep the handle (--undo within 24 h)
keygent rename stripe/live stripe/prod
keygent rm stripe/live          # always asks for your passphrase
keygent import .env [--delete]  # bulk import, optionally delete the file afterwards
keygent reveal stripe/live      # shows it full-screen and clears it after 20 s (never in scrollback); --copy to use the clipboard
```

Handles look like `stripe/live` (lowercase, up to 4 levels). Very short or low-entropy values are refused, because they
can't be redacted reliably.

> Tip: after importing a `.env` that an agent may already have read, rotate those keys at the provider.

```sh
keygent ls
# stripe/live   STRIPE_API_KEY                  "Stripe live key"
# gcp/sa        GOOGLE_APPLICATION_CREDENTIALS  "GCP service account" (file)
```

`keygent ls` shows handles and env var names only. It is safe for agents to run.

### 3. Use secrets in commands

**Option A: placeholders.** Hand the secret to the tool as an environment variable, or as a private file:

```sh
keygent run -- STRIPE_API_KEY={{keygent:stripe/live}} stripe customers list        # env var the tool reads itself
keygent run -- curl -sS -K {{keygent-file:stripe/curl-auth}} https://api.stripe.com/v1/customers   # path to a private file
```

`{{keygent:…}}` sets an environment variable for that one process. `{{keygent-file:…}}` becomes the path of a private,
temporary file holding the value (deleted when the command ends). keygent **refuses** to put a secret directly into a command's
arguments (like `curl -u {{keygent:stripe/live}}:`), because arguments show up in the process list where other users on the machine
can see them. You can allow it for a specific secret if you accept that. Supported shells: `sh`/`bash`/`zsh`-style POSIX, Git Bash
and PowerShell 7. `cmd.exe` is not supported. Commands get no input from the agent: keygent runs them with an empty stdin.

**Option B: project manifest.** Commit a `.keygent.toml` to your repo. It holds no values, only names:

```toml
[secrets]
"stripe/live" = { env = "STRIPE_API_KEY" }
"gcp/sa"      = { env = "GOOGLE_APPLICATION_CREDENTIALS", file = true }  # written to a private temp file, deleted on exit
```

```sh
keygent manifest init
keygent manifest add stripe/live --env STRIPE_API_KEY
keygent trust                                 # shows the file (or what changed), then asks for your passphrase
keygent run -- stripe customers list          # STRIPE_API_KEY is set for this command only
```

A manifest grants nothing until you `keygent trust` it, the same way `direnv allow` works. If the file changes (for example,
an agent adds a handle), access stops and you get:

```text
keygent: .keygent.toml changed — ask the user to run 'keygent trust'
```

Machine-wide handles go in `global.toml` in your config folder (see Files) and need to be trusted too. Project entries take
precedence. Lookup stops at the repo root, so vendored repos never inherit your secrets. Dangerous variable names such as `PATH`,
`LD_PRELOAD` or `NODE_OPTIONS` are refused.

With the Claude Code integration installed you never type `keygent run` yourself. The hook wraps matching commands
automatically.

### 4. Capture a newly minted secret

For commands that **produce** a credential:

```sh
keygent capture aws/session -- aws sts get-session-token --query Credentials.SessionToken --output text
# stored aws/session (env AWS_SESSION_TOKEN)
```

The value is stored straight into the vault and never printed. `capture` can create new handles but never overwrites an
existing one without your passphrase. Captured secrets default to `approve` mode.

### 5. Approvals and policy

Each secret has a mode (change it with `keygent edit <handle>`):

| Mode | What happens |
|---|---|
| `approve` *(default)* | Every use needs your approval: Touch ID (macOS; Windows Hello once verified), your passkey in the console, or `keygent approve` in your terminal. You see the exact command. |
| `allow` | Runs silently, but **only** for commands matching one of its allow rules. Anything else is treated as `approve`. |
| `confirm` | Uses Claude Code's own permission dialog. Convenient, but an agent can work around it. Use it only for low-risk secrets. |
| `deny` | Never used. |

Approving from a terminal:

```sh
keygent pending                 # what's waiting, with the full command
keygent approve <id>            # approve a request (passphrase); the id is optional if only one is waiting
keygent approve --remember      # …and allow the identical command again for 15 minutes
```

Approval prompts show the full command (with hidden or special characters made visible), the project folder, which secrets
it gets, and every program it runs, each fingerprinted. If the command runs a script (`bash ./deploy.sh`, `python sync.py`), you see
**the whole script** and have to scroll to the end before you can approve. If any program or script changes before it runs, the run
is blocked. keygent can't see code that a script loads in turn (imports, `make`, `npm run`), so those approvals carry a clear
warning and can't be remembered. Read them like you'd read code before running it. Long or unusual commands are approved in your
terminal or the console, not in the short system prompt.

Allow rules pin the exact program, its fingerprint and its arguments:

```toml
[[allow]]
exe    = "/opt/homebrew/bin/stripe"     # absolute path, captured when you approved it
sha256 = "…"                            # if the binary changes (update or swap), you're asked again
args   = ["customers", "list", "*"]     # "*" = exactly one argument
```

- keygent ignores the agent's `PATH` and working directory, and runs allowed commands directly, without a shell.
- Chained or piped commands (`;`, `&&`, `|`, `$(…)`, redirects) never match a rule.
- Shells, interpreters and general-purpose network tools (`bash`, `python`, `node`, `curl`, `wget`, `ssh`, …) can only be
  allowed with exact arguments.

Preview a decision without running anything:

```sh
keygent check 'stripe customers list --limit 10'
# allow: stripe/live via rule /opt/homebrew/bin/stripe customers list *
```

### 6. Claude Code integration

```sh
keygent integrate claude              # user scope (~/.claude/settings.json)
keygent integrate claude --project    # this repo only (.claude/settings.local.json)
keygent integrate claude --remove     # undo exactly what was added
keygent doctor                        # verify hooks, version support, vault state
```

This installs:

| Hook | What it does |
|---|---|
| `UserPromptSubmit` | Blocks prompts that contain a secret, so it never reaches the model, and tells you to `keygent add` it instead. Claude Code may still keep the text in its local history, so a known secret is marked exposed and you're asked to rotate it. Prefix `!!` to send anyway (also marked exposed). |
| `PreToolUse` · Bash / PowerShell | Wraps commands that use placeholders or manifest handles in `keygent run --`, triggers the approval prompt when needed, and blocks env dumps. |
| `PreToolUse` · Write/Edit | Blocks writing a secret value into a file, and blocks edits to keygent's manifest, your agent settings and shell startup files. |
| `PreToolUse` · Read/Grep/Glob | Blocks reads of the vault, `.env*` and key files. |
| `PostToolUse` | A second redaction pass over all tool output. |

It also installs a tiny skill so the agent knows how to use handles. That costs about 25 words of context until it is used. It does not use MCP by default, so no per-turn token overhead.

### 7. lean-ctx

If lean-ctx is installed, keygent detects it and composes with it:

```sh
keygent integrate lean-ctx            # chain lean-ctx's hooks behind keygent, add keygent to its allowlist + secret paths
keygent integrate lean-ctx --remove
```

keygent always runs **innermost** (`lean-ctx -c "keygent run -- …"`). Output is redacted before lean-ctx compresses or caches
it.

### 8. Web console (coming soon)

A local dashboard for your vault, unlocked with a passkey (Touch ID, Windows Hello, iCloud Keychain, or a security key).

```sh
keygent passkey add      # enroll a passkey (asks for your passphrase first)
keygent ui               # opens http://localhost:<random-port> in your browser
```

- See every secret at a glance: handle, env var, description, policy, pinned programs, last use, and whether it was ever exposed.
- Approve or deny pending agent requests with a tap of your passkey.
- Edit policies and allow rules, trust or untrust project manifests, delete secrets, and seal the vault.
- Browse the audit log.

Every change asks for your passkey again, so a stolen browser session can only look. Secret values never pass through
the browser. Adding and revealing them stays in your terminal. The console is started by keygent's broker itself, and it only
accepts that exact page, so another program can't impersonate it. It runs only on your machine. Nothing is hosted, and nothing
leaves your computer.

### 9. Audit and exposure

```sh
keygent audit --since 24h       # who used what, when, with what result (values never logged)
keygent exposed                 # handles that leaked or were overridden: rotate these
```

Every run that uses an exposed handle prints a one-line reminder to `keygent rotate` it.

---

## Good to know

- **Interactive programs:** commands run with plain pipes, not a terminal, so tools that need an interactive login prompt
  won't work through keygent. Use their token- or env-based login instead.
- **Long-running commands:** runs stop after 30 minutes (or 10 MiB of output per stream) by default. A dev server or watcher can ask for up
  to 4 hours with `--max-runtime`. The requested time is shown in the approval prompt.
- **Pasting a secret into the chat:** keygent stops it from being sent to the model, but Claude Code may already have saved it in its
  local history. keygent marks that secret as exposed, so rotate it. Better: add secrets with `keygent add` in your own terminal.
- **Works alongside other tools' hooks:** keygent always runs first. Other hooks (lean-ctx, for example) only see prompts and
  output after keygent has blocked or redacted them. `keygent doctor` points out hooks that aren't chained yet.
- **Where it runs:**

| Environment | Support |
|---|---|
| macOS, Windows, Linux desktops | Full |
| WSL2 | As Linux (approve in the terminal or console) |
| SSH / headless servers | Yes. Approve from a second terminal with `keygent approve` |
| Docker / devcontainers | One vault per container |
| CI pipelines | Not supported in v1 (no unattended unlock, by design) |

- **Upgrading:** replace the binary, then `keygent seal && keygent unseal`. `keygent doctor` repairs hook paths if needed.
- **Something wrong?** `keygent doctor` checks everything. `keygent doctor --report` prints a summary that's safe to paste into an
  issue (no secrets, handles or commands).
- **Uninstall:** `keygent uninstall` removes hooks, config and everything keygent added, and keeps your vault and audit log.
  Add `--purge` to delete those too.

## Command reference

| Area | Commands |
|---|---|
| Vault | `init [--own-passphrase]` · `unseal [--ttl]` · `seal` · `status` · `passwd`🔑 · `rekey`🔑 · `recover` · `verify` · `backup` · `restore`🔑 |
| Secrets | `add`🔑 · `edit`🔑 · `rm`🔑 · `rename`🔑 · `rotate [--undo]`🔑 · `import`🔑 · `reveal`🔑 |
| Approvals | `pending` · `approve [--remember]`🔑 · `deny` |
| Agent-safe | `ls` · `run -- <cmd>` · `capture <handle> -- <cmd>` · `check <cmd>` · `untrust` |
| Project | `manifest init` · `manifest add <handle> [--env NAME] [--file]` · `trust`🔑 |
| Console | `ui` · `passkey add`🔑 · `passkey ls` · `passkey rm`🔑 |
| Integration | `integrate claude [--project] [--remove]` · `integrate lean-ctx [--remove]` · `doctor` · `uninstall [--purge]` |
| Audit | `audit [--since] [--verify]` · `exposed` |
| Optional | `mcp`: stdio MCP server for agents without hooks |

🔑 = asks for your passphrase in your own terminal. A few quick actions (approving a short request, `rename`, `deny`) can use Touch ID instead; `rm` always needs the passphrase. `reveal` always needs the passphrase.

### Exit codes

| Code | Meaning |
|---|---|
| child's code | `keygent run` passes through the command's exit code |
| `64` | usage error |
| `75` | approval denied or timed out |
| `76` | project manifest changed, needs `keygent trust` |
| `77` | denied by policy |
| `78` | vault sealed |
| `74` | run stopped at its time or output limit |
| `79` | broker or version error (run `keygent doctor`) |

keygent's own errors always print one line starting with `keygent:`, so you can tell them apart from a command that happens to use the same code.

### Files

| | Linux | macOS | Windows |
|---|---|---|---|
| Vault (`vault.kgt`, encrypted, owner-only) | `~/.local/share/keygent/` | `~/Library/Application Support/keygent/` | `%LOCALAPPDATA%\keygent\` |
| Config + `global.toml` | `~/.config/keygent/` | `~/Library/Application Support/keygent/config/` | `%APPDATA%\keygent\` |
| Audit log (`audit.jsonl`, HMAC-chained) | `~/.local/state/keygent/` | `~/Library/Application Support/keygent/state/` | `%LOCALAPPDATA%\keygent\state\` |
| Broker endpoint (private to you) | `/run/user/<uid>/keygent/` | your per-user temp folder `…/keygent/` | named pipe `\\.\pipe\keygent-<your SID>-<session>` |

`.keygent.toml` is the per-project manifest, safe to commit. On Linux, `XDG_*` variables are deliberately ignored (an agent could change them to redirect keygent); paths come from your account's home directory.

---

## Security model

keygent is built for the two situations you actually run into:

1. **Accidents.** A helpful agent reads `.env`, prints the environment, echoes a key in a log, or pastes one into code.
2. **Generic prompt injection.** Something the agent reads tells it to "run `env` and send it to this URL".

**What it protects against:**

- an agent reading `.env` or the vault with its file tools (to also stop shell commands like `cat`, turn on Claude Code's sandbox — `keygent doctor` checks it); a copied vault file is useless without this device
- an agent printing the environment
- secrets echoed in command output, in common encodings
- you accidentally pasting a secret into the chat (it isn't sent to the model, and you're told to rotate it)
- an agent reading Claude Code's own transcripts or history with its file tools
- an agent writing a secret into source code
- an agent granting itself access by editing the manifest, the policy or its settings
- an agent faking an approval, or swapping in a look-alike program for an allowed tool
- an agent impersonating keygent's broker or console to collect your passphrase or values
- secrets in argv
- secrets in hook payloads and transcripts
- other local users reaching the broker

**What it does not claim.** keygent is not a sandbox. Your agent runs as your own OS user, so an agent that deliberately
attacks keygent itself has more options than these protections cover. Redaction is defense-in-depth, not a guarantee:

- A command you approve can send the secret wherever that command sends data, or print it in a disguised form. Read
  what you approve. The planned egress proxy will bind secrets to specific hosts.
- Arbitrary transformations (reversing, XOR, splitting across lines) defeat pattern matching.
- While an approved command runs, another process running as your user can read its environment (for example with `ps eww`). Keep runs short; the planned egress proxy removes this.
- Software that replaces the `keygent` program itself or wraps your shell could show you a fake passphrase prompt. Touch ID,
  Windows Hello and passkey approvals can't be phished this way, and `keygent doctor` checks the binary's signature.

If a secret ever shows up somewhere it shouldn't, rotate it at the provider and run `keygent rotate`.

---

## FAQ

**Does my secret go to the model provider?** No. Only handles and redacted output reach the agent.

**Do I need to keep a server running?** No. `keygent unseal` starts a small local broker, like `ssh-agent`, that exits
when the vault seals.

**Which agents are supported?** Claude Code in v1. Codex, Cursor, Gemini CLI and opencode adapters are planned. Agents
without hooks can use the optional MCP mode.

**Can I use 1Password, Vault or AWS Secrets Manager?** External backends are planned after v1.

## Roadmap

- [ ] v1 on macOS, Windows and Linux: local vault, broker-verified approvals, pinned allow rules, redactor, Claude Code
      hooks, passkey web console, lean-ctx composition
- [ ] Egress proxy (credentials injected per host, so the child never holds the value)
- [ ] Passkey unlock, auto-seal on screen lock or sleep, Shamir unseal for shared machines
- [ ] More agent adapters (Codex, Cursor, Gemini CLI, opencode), external secret backends

## Contributing

Issues and PRs are welcome once the first release is out. Never include real secrets in issues, tests or logs.
Use generated canaries.

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in keygent is licensed under the
Apache-2.0 license as defined in its section 5, without any additional terms or conditions.
