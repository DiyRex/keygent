# ADR 0003 — Trust model: same-uid agent, broker-held plaintext

- **Status:** accepted
- **Date:** 2026-11-15
- **Verified against:** design review of SPEC v1. The OS facts listed below should be re-checked in the Phase 0 platform spike.

## Context

The AI agent runs as the **same OS user** as the human. Consequences:

- It can connect to any socket the user can, so a peer-uid check stops other users but not the agent.
- It can read `/proc/<pid>/environ` of same-uid processes on Linux. Access is a `PTRACE_MODE_READ` check, which Yama
  `ptrace_scope=1` does not restrict; Yama restricts attach only. It can also run `ps eww` (macOS, Linux).
- It can run any subcommand directly, including `keygent hook pre` with forged JSON, and can fake a TTY with `script`.
- It can edit any file the user can edit: manifests, agent settings, hook config.
- It **cannot** know the passphrase, pass OS user-presence checks, or read the memory of a process that is non-dumpable, has PT_DENY_ATTACH and is mlocked
  (Linux; on macOS PT_DENY_ATTACH is weaker and should be verified).

SPEC v1 assumed hooks, TTY checks and the socket check were security boundaries. Under the facts above, they are not.

## Options

1. **Keep the v1 design and document it.** Simple, but plaintext crosses the socket to any same-uid client, and the manifest and
   `ask` mode can be bypassed by T2-level behavior.
2. **Broker-held plaintext (chosen).** Only the broker process ever holds values or redaction patterns. It spawns
   children itself and returns only redacted output. Authorization relies on the passphrase, a trusted manifest hash and
   single-use grants.
3. **Separate-uid broker** (setuid helper or system service). Stronger against T3, but needs root to install, is
   cross-platform heavy, and children still run as the user, so their env would still be readable.
4. **Egress proxy.** The child never holds the value. This is the only real defense against T3. It is HTTP-only and needs CA trust per run.

## Decision

Adopt **option 2 for v1**, scoped to attacker tiers T1 (accidental) and T2 (generic injected exfiltration). Keep the
**option 4 design hooks** (`hosts` in policy) and build it in Phase 6. Reject option 3 for now. Every security claim names
its tier.

## Consequences

- The broker grows: process spawning, stdin forwarding, signal and process-group handling, and per-stream redaction. More code
  is a cost we accept for the boundary.
- The `run` client is thin, and it is safe that the agent can call it.
- **Approvals must be observed by the broker** (native UV with broker-supplied text, terminal passphrase proof, or a passkey on the
  broker-launched console). A hook or client claiming "approved" is never trusted. See ADR 0007. Claude Code's dialog is T1-only.
- **Allow rules pin executables** (absolute path + hash) and ignore the client environment, because PATH and cwd are attacker-controlled (ADR 0007).
- An agent (a known **T2** gap since SPEC v6) can still race `/proc/<child>/environ` while a child runs. This is documented in THREATS.md and tracked as a known
  failure in the leak suite until the egress proxy exists.
- Re-check this ADR if keygent ever gains a privileged component, or if Claude Code ships per-tool sandboxing that runs
  agent commands under a different uid or namespace.
