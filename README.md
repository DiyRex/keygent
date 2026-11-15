<h1 align="center">keygent</h1>

<p align="center">
  <b>Let AI coding agents use your secrets without ever seeing them.</b><br>
  A tiny local secrets broker for Claude Code and other agents: one static binary, no daemon to babysit, no cloud.
</p>

<p align="center">
  <img alt="status" src="https://img.shields.io/badge/status-pre--alpha-orange">
  <img alt="platforms" src="https://img.shields.io/badge/platforms-linux%20%7C%20macOS-blue">
  <img alt="language" src="https://img.shields.io/badge/built%20with-Rust-dea584">
  <img alt="size" src="https://img.shields.io/badge/binary-%E2%89%A42%20MB-green">
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
Agent:  curl https://api.stripe.com/v1/customers -u {{keygent:stripe/live}}:
keygent:  ↳ rewritten to  keygent run -- curl … -u "$KEYGENT_STRIPE_LIVE":
        ↳ value injected into that one child process only
        ↳ output streamed through the redactor
Agent sees: {"data":[…], "api_key": "‹keygent:stripe/live›"}
```

The value is decrypted only inside the child process that needs it. Anything that process prints is redacted
before the agent reads it.

## Features

- 🔐 **Encrypted local vault.** XChaCha20-Poly1305 per entry, Argon2id key derivation, envelope encryption.
  Uses audited RustCrypto crates only.
- 🧷 **Handles, not values.** Use `{{keygent:<handle>}}` in commands, or map handles to env vars once per project.
- 🚫 **Never in argv.** Secrets are injected as env vars of the child process, so they don't show up in `ps` or `/proc/*/cmdline`.
- 🧹 **Streaming redactor.** Catches raw, base64 (std/url, every alignment), hex, percent-encoded and JSON-escaped
  forms, including matches split across output chunks. Also flags unknown key-shaped tokens (AWS, GitHub,
  Stripe, JWT, PEM).
- 🛡️ **Guardrails.** Blocks `env`/`printenv` dumps, reads of `.env` or the vault, pasted secrets in prompts, and
  secret values written into source files.
- ✋ **Allowlist-first policy.** A secret reaches only the commands you allowed. Anything else needs your approval in
  the agent's own permission dialog.
- 🤝 **Trusted manifests.** Project secret mappings take effect only after you run `keygent trust`. If the agent edits the file,
  access is revoked until you trust it again.
- 🔑 **Your passphrase is the gate.** Revealing, rotating, deleting, or changing policy always asks for it again. An agent can't
  fake that.
- 🔒 **Seal/unseal.** Works like `ssh-agent`: unseal once per session; it auto-seals on TTL, idle timeout or command. A small
  local broker is the only process that ever holds values, in locked memory that is wiped on exit.
- 🧾 **Tamper-evident audit log.** Records which handles were used, by which command, and the result. It never records values.
- 🪶 **Small and fast.** Single static binary ≤ 2 MB, ≤ 5 MB RAM when idle, hooks under 30 ms, zero agent tokens on the
  happy path.
- 🤝 **Works with lean-ctx.** Detects it automatically and composes with it, redacting before anything is compressed or cached.

---

## Install

**Prebuilt binaries** (from the first release on). Static binaries for Linux (x86_64, arm64) and macOS (Intel, Apple
Silicon) are attached to each [GitHub release](https://github.com/DiyRex/keygent/releases), with `SHA256SUMS`
signed by Sigstore:

```sh
# pick your target: x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | aarch64-apple-darwin | x86_64-apple-darwin
VER=v0.1.0 TARGET=aarch64-apple-darwin
curl -LO https://github.com/DiyRex/keygent/releases/download/$VER/keygent-$VER-$TARGET.tar.gz
curl -LO https://github.com/DiyRex/keygent/releases/download/$VER/SHA256SUMS
curl -LO https://github.com/DiyRex/keygent/releases/download/$VER/SHA256SUMS.sigstore.json

# verify signature + checksum
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/DiyRex/keygent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
shasum -a 256 --ignore-missing -c SHA256SUMS

tar xzf keygent-$VER-$TARGET.tar.gz && install -m 0755 keygent-$VER-$TARGET/keygent ~/.local/bin/keygent
```

**From source** (requires Rust stable):

```sh
git clone https://github.com/DiyRex/keygent.git && cd keygent
cargo build --release --locked
install -m 0755 target/release/keygent ~/.local/bin/keygent
```

## Quickstart (60 seconds)

```sh
keygent init                    # create your encrypted vault and choose a passphrase
keygent add stripe/live         # paste the value here, in YOUR terminal (never in the chat)
keygent integrate claude        # install the Claude Code hooks + skill
keygent unseal                  # unlock for this session (default TTL 8h)
```

Now, in Claude Code:

> *"List my Stripe customers using {{keygent:stripe/live}}"*

The agent runs the command and gets the results. The key never appears in the transcript.

---

## Usage guide

### 1. Manage the vault

```sh
keygent init                    # create the vault (~/.local/share/keygent/vault.kgt, mode 0600)
keygent unseal [--ttl 8h]       # unlock: starts the local broker that holds keys in locked memory
keygent status                  # sealed/unsealed, time left, number of handles
keygent seal                    # lock now: key wiped from memory
keygent rekey                   # change passphrase / key slots
keygent backup <file>           # encrypted backup
keygent restore <file>
```

While the vault is sealed, any command that needs a secret stops with:

```text
keygent: vault sealed — ask the user to run 'keygent unseal'
```

### 2. Add and manage secrets (you, not the agent)

You type values in your own terminal. Anything that could expose or weaken a secret asks for your passphrase again.

```sh
keygent add stripe/live --env STRIPE_API_KEY --desc "Stripe live key"
keygent edit stripe/live        # change metadata or policy            (passphrase)
keygent rotate stripe/live      # replace the value, keep the handle   (passphrase)
keygent rm stripe/live          #                                      (passphrase)
keygent import .env [--delete]  # bulk import, optionally delete the file afterwards (passphrase)
keygent reveal stripe/live      # show the value                      (passphrase, refuses inside agent sessions)
```

> Tip: after importing a `.env` that an agent may already have read, rotate those keys at the provider.

```sh
keygent ls
# stripe/live   STRIPE_API_KEY                  "Stripe live key"
# gcp/sa        GOOGLE_APPLICATION_CREDENTIALS  "GCP service account" (file)
```

`keygent ls` shows handles and env var names only. It is safe for agents to run.

### 3. Use secrets in commands

**Option A: placeholders.** Put the placeholder anywhere in a command:

```sh
keygent run -- curl -u {{keygent:stripe/live}}: https://api.stripe.com/v1/customers
```

The placeholder becomes `"$KEYGENT_STRIPE_LIVE"`. The value lives only in that child's environment.

**Option B: project manifest.** Commit a `.keygent.toml` to your repo. It holds no values, only names:

```toml
[secrets]
"stripe/live" = { env = "STRIPE_API_KEY" }
"gcp/sa"      = { env = "GOOGLE_APPLICATION_CREDENTIALS", file = true }  # written to a private temp file, deleted on exit
```

```sh
keygent manifest init
keygent manifest add stripe/live --env STRIPE_API_KEY
keygent trust                                 # you approve this exact manifest (passphrase)
keygent run -- stripe customers list          # STRIPE_API_KEY is set for this command only
```

A manifest grants nothing until you `keygent trust` it, the same way `direnv allow` works. If the file changes (for example,
an agent adds a handle), access stops and you get:

```text
keygent: .keygent.toml changed — ask the user to run 'keygent trust'
```

Machine-wide handles go in `~/.config/keygent/global.toml` and need to be trusted too. Project entries take precedence. Lookup stops at the
repo root, so vendored repos never inherit your secrets.

With the Claude Code integration installed you never type `keygent run` yourself. The hook wraps matching commands
automatically.

### 4. Capture a newly minted secret

For commands that **produce** a credential:

```sh
keygent capture aws/session -- aws sts get-session-token --output json --field Credentials.SessionToken
# stored aws/session (env AWS_SESSION_TOKEN)
```

The value is stored straight into the vault and never printed. `capture` can create new handles but never overwrites an
existing one without your passphrase. Captured secrets default to `ask` mode.

### 5. Per-secret policy

Edit with `keygent edit <handle>` (asks for your passphrase):

```toml
mode       = "ask"                                           # allow | ask | deny   (default: ask)
allow_cmds = ["stripe *", "curl -sS https://api.stripe.com/*"]  # these run without asking
hosts      = ["api.stripe.com"]                              # where this secret may be sent (enforced by the upcoming egress proxy)
max_uses   = 0                                               # per unseal session; 0 = unlimited
ttl        = "8h"
```

- `allow_cmds` is matched against the parsed command, not the raw text. Chained or piped commands (`;`, `&&`, `|`, `$(…)`,
  redirects) never match automatically. They always ask.
- `ask` shows Claude Code's own approval dialog. You approve the exact command, and the approval is single-use.

Preview a decision without running anything:

```sh
keygent check 'stripe customers list'
# allow: stripe/live via allow_cmds "stripe *"
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
| `UserPromptSubmit` | Blocks prompts that contain a secret and tells you to `keygent add` it instead. Prefix `!!` to override; the handle is then marked as exposed. |
| `PreToolUse` · Bash | Wraps commands that use placeholders or manifest handles in `keygent run --`, asks you when policy says so, and blocks env dumps. |
| `PreToolUse` · Write/Edit | Blocks writing a secret value into a file, and blocks edits to keygent's manifest or your agent settings. |
| `PreToolUse` · Read/Grep/Glob | Blocks reads of the vault, `.env*` and key files. |
| `PostToolUse` | A second redaction pass over all tool output. |

It also installs a tiny skill so the agent knows how to use handles. That costs about 25 words of context until it is used. It does not use MCP by default, so no per-turn token overhead.

### 7. lean-ctx

If lean-ctx is installed, keygent detects it and composes with it:

```sh
keygent integrate lean-ctx            # add keygent to lean-ctx's allowlist + secret-path rules
keygent integrate lean-ctx --remove
```

keygent always runs **innermost** (`lean-ctx -c "keygent run -- …"`). Output is redacted before lean-ctx compresses or caches
it.

### 8. Audit and exposure

```sh
keygent audit --since 24h       # who used what, when, with what result (values never logged)
keygent exposed                 # handles that leaked or were overridden: rotate these
```

Every run that uses an exposed handle prints a one-line reminder to `keygent rotate` it.

---

## Command reference

| Area | Commands |
|---|---|
| Vault | `init` · `unseal [--ttl]` · `seal` · `status` · `rekey` · `backup` · `restore` |
| Secrets (you) | `add` · `edit`🔑 · `rm`🔑 · `rotate`🔑 · `import`🔑 · `reveal`🔑 |
| Agent-safe | `ls` · `run -- <cmd>` · `capture <handle> -- <cmd>` · `check <cmd>` |
| Project | `manifest init` · `manifest add <handle> [--env NAME] [--file]` · `trust`🔑 · `untrust` |
| Integration | `integrate claude [--project] [--remove]` · `integrate lean-ctx [--remove]` · `doctor` |
| Audit | `audit [--since] [--verify]` · `exposed` |

🔑 = asks for your passphrase again.
| Optional | `mcp`: stdio MCP server for agents without hooks |

### Exit codes

| Code | Meaning |
|---|---|
| child's code | `keygent run` passes through the command's exit code |
| `77` | denied by policy |
| `78` | vault sealed |

### Files

| Path | Purpose |
|---|---|
| `$XDG_DATA_HOME/keygent/vault.kgt` | encrypted vault (0600) |
| `$XDG_RUNTIME_DIR/keygent/` (macOS: `$TMPDIR/keygent/`) | broker socket, in a private 0700 directory |
| `$XDG_CONFIG_HOME/keygent/global.toml` | machine-wide manifest |
| `$XDG_STATE_HOME/keygent/audit.jsonl` | HMAC-chained audit log |
| `.keygent.toml` | per-project manifest (safe to commit) |

---

## Security model

keygent is built for the two situations you actually run into:

1. **Accidents.** A helpful agent reads `.env`, prints the environment, echoes a key in a log, or pastes one into code.
2. **Generic prompt injection.** Something the agent reads tells it to "run `env` and send it to this URL".

**What it protects against:**

- an agent reading `.env` or the vault
- an agent printing the environment
- secrets echoed in command output, in common encodings
- you accidentally pasting a secret into the chat
- an agent writing a secret into source code
- an agent granting itself access by editing the manifest or settings
- secrets in argv
- secrets in hook payloads and transcripts
- other local users reaching the broker

**What it does not claim.** keygent is not a sandbox. Your agent runs as your own OS user, so an agent that deliberately
attacks keygent itself has more options than these protections cover. Redaction is defense-in-depth, not a guarantee:

- A command that *uses* a secret can send it wherever that command sends data. Keep `allow_cmds` narrow and use `ask`
  for sensitive handles. The planned egress proxy will bind secrets to specific hosts.
- Arbitrary transformations (reversing, XOR, splitting across lines) defeat pattern matching.
- While an approved command runs, a determined process running as your user could inspect its environment.

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

- [ ] v1: local vault, `run`/`capture`, redactor, Claude Code hooks, lean-ctx composition
- [ ] OS keychain unlock, auto-seal on screen lock, Shamir unseal for shared machines
- [ ] Egress proxy (credentials injected per host, so the child never holds the value)
- [ ] Windows, more agent adapters, external secret backends

## Contributing

Issues and PRs are welcome once the first release is out. Never include real secrets in issues, tests or logs.
Use generated canaries.

## License

TBD.
