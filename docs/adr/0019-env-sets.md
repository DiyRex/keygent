# ADR 0019 — Env sets: a project's environment as one named group ("sampath ipg stage")

- **Status:** proposed
- **Date:** 2026-11-28
- **Verified against:** keygent `feat/broker-and-run`: handle grammar (`vault/names.rs`), manifest subset (`policy/manifest.rs`)

## Context

A real integration needs several variables at once. For a payment gateway (IPG) that might be merchant id, API key, secret,
callback URL and environment URL. Each variable also exists for `stage` and for `prod`.

The owner wants to:

- enter all of them in one go;
- say "integrate sampath ipg stage into this app";
- have the agent pick the **stage** values and never the prod ones;
- wire them into the app the way its `.env` expects;
- keep every value out of chat, output and disk.

Today each value is a separate handle. A project can list handles in `.keygent.toml` (SPEC §5.6). There is no group, no alias
and no bulk entry except `import .env`.

**What the owner asked for vs. the vault rule**

The owner asked for the values to land in the app's `.env` file. Writing real values to `.env` means:

- plaintext on disk in the repo, which any same-user process or agent can `cat` (T1);
- which breaks "never keep plaintext stored anywhere";
- and SPEC §5.10 already blocks reads of `.env*` because of this.

So this ADR keeps the **developer experience** of `.env` (variable names, the app reads `process.env.X` / `os.environ`, a
dotenv loader still works). Values exist only in the process keygent launches.

## Decision

### 1. Model

**What a set is**
- An **env set** is a handle prefix of the form `<project>/<env>`, for example `sampath-ipg/stage`.
- It has metadata stored in the encrypted index:
  - `description` (≤ 200 chars);
  - `aliases`, used to match natural language: `["sampath ipg stage", "sampath staging"]`;
  - `tier`: `dev`, `stage` or `prod`;
  - an optional default mode for its members.

**Members**
- Members are ordinary handles under the prefix, for example `sampath-ipg/stage/merchant_id`.
- Each member has its own `env_name` (`MERCHANT_ID`).
- No new secret type exists. Every v1 rule applies per member: entry AEAD, the redactor, rotate and rm.

**Prod sets**
- `tier = prod` sets cannot be put in `allow` mode. Every run needs approval.
- The approval text shows the set name and **PROD** first (`render_for_approval()`).

**Limits**
- At most 100 sets and 50 members per set.
- The handle cap of 1,000 still applies.

### 2. Entry: one paste, many values

**`keygent set add sampath-ipg/stage [--tier stage] [--alias "sampath ipg stage"]`** (auth)
- Takes a dotenv-format block, entered in one of two ways:
  - pasted into the terminal (echo off, ends with an empty line or Ctrl-D);
  - `--from-file .env.stage --delete`, which deletes the file after import.
- Each `KEY=value` line becomes the member `<set>/<key in lower case>` with `env_name = KEY`.
- Duplicate keys, reserved env names (SPEC §5.6) and over-length values are refused **before anything is written**.
- Values are never echoed.
- The summary shows names and lengths only.

**Other commands**
- `keygent set rotate <set>`: same input. It replaces listed members and keeps the others, unless `--exact` is given.
- `keygent set edit <set>`: metadata (description, aliases, tier, mode). Auth.
- `keygent set rm <set>`: auth. Lists the members first.
- `keygent set ls [--json]`: names, tiers, aliases, descriptions and member env names. **Never values.** Agent-safe.

**Web console** (Phase 4, ADR 0005 amendment)
- A "New env set" form with a textarea for the dotenv block.
- Write-only: values are sent to the broker once and never rendered back.
- Viewing a value later needs a per-action passkey assertion (Touch ID / Windows Hello).
- The response is `Cache-Control: no-store`. The field is cleared after submit and never kept in browser storage.

### 3. Use by an agent: "integrate sampath ipg stage"

**1. Resolve.**
- The skill tells the agent to run `keygent set ls --json` and match the user's words to the `aliases`.
- An ambiguous match, or any match where both a stage and a prod set fit, is **asked back** to the user. The agent never chooses.
- A prod set is used only if the user named it exactly. The broker shows PROD in the approval anyway, so a wrong pick
  can't run silently.

**2. Wire the code.**
- The agent writes code that reads the env names: `process.env.MERCHANT_ID`, `os.environ["MERCHANT_ID"]`, …
- It writes `.env.example` with **names only**.
- It adds the set to the project manifest:

  ```toml
  # .keygent.toml
  [sets]
  use = ["sampath-ipg/stage"]
  ```

- The human runs `keygent trust` once. The manifest changed, so it must be re-trusted (SPEC §5.6).

**3. Run.**
- The app is started with `keygent run -- npm run dev` (or `pytest`, `cargo run`, …).
- The broker sets every member's `env_name` in that child's environment.
- One approval covers the whole set for that exact command (the grant key binds the set name and the member list).
- Output is redacted for every member's value.

**4. Existing dotenv files keep working.**
- dotenv loaders (Node `dotenv`, `python-dotenv`, Vite, Next.js) do **not** override variables already in the environment.
- So the injected values win over a `.env` that holds placeholders or is missing.

**If a tool insists on reading a real file**
- `keygent run --env-file <name> -- <cmd>` makes the broker write a dotenv file of the set's values into a private binding:
  - Linux: memfd;
  - macOS and Windows: an owner-only run-dir file, deleted when the run ends;
  - it is never in the repo.
- The child gets the binding's path in `KEYGENT_ENV_FILE`. A mapping such as `DOTENV_CONFIG_PATH=$KEYGENT_ENV_FILE` is set
  in the manifest.
- This is the SPEC §5.6 file-binding mechanism applied to a set.

**Never**
- keygent never writes values into the project's `.env`.
- `keygent set export` does not exist.
- Any value on disk beyond the vault and the run-scoped bindings is a design bug.

### 4. Audit

`run`, `approve` and `set *` records carry `set` (ADR 0018). `audit stats --by set` answers "how often was sampath ipg stage
used, and by which agent and tool".

## Consequences

**Format**
- FORMATS index: a `sets` table (prefix, description, aliases, tier, mode). The manifest grammar gets `[sets] use = [...]`.
- `set add` reuses `import`'s dotenv parser, with stricter checks.

**SPEC**
- §5.1 gains the `set` command family.
- §5.6 gains `[sets]`.
- §5.11 changes: the console may take **value entry (write-only)** and **gated reveal**. This reverses "No reveal and no value
  entry" and needs a SPEC §17 row.

**Skill (Phase 3)**
- The skill text teaches alias resolution and the "ask on ambiguity; never pick prod" rule.

**Tests**
- Leak tests: no member value in stdout or stderr; no value in any file under the project dir after a run.
- `.env` placeholders are overridden.
- A prod set in a rule is refused.
- An alias that matches both stage and prod makes the skill ask (golden transcript).
