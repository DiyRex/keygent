# ADR 0014 — Phase 2 grants, approvals and run: implementation choices

- **Status:** proposed
- **Date:** 2026-11-16
- **Verified against:** keygent `phase-2-broker` working tree; macOS 26 (Darwin 25.6) and Linux `rust:1-bookworm` container,
  `cargo test --features test-profile` (103 unit + 23 end-to-end tests on both)

## Context

P2-M3 implements SPEC §5.5.2 (grants, approvals) and §5.7 (`run`). A few points in the spec are underspecified, internally
inconsistent, or need a wire-level choice. This ADR records what was built so review can accept or redirect it.

## Options and decisions

1. **`Approve` wire shape.** ADR 0004 lists `Auth{proof_c}` → `Authed`, then `Approve{grant_id, grant_key_hash}`. Since `proof_c`
   binds `H(request)` anyway, the request has to be known before `Auth`. **Built:** one `Approve` frame carrying
   `{proof_c, grant_id, grant_key, remember}`. `proof_c = HMAC(K_auth, enc("kg/v1/client")‖enc(nb)‖enc(nc)‖enc(H(id‖key‖remember)))`.
   The security properties are the same: per-connection nonces, and the key the human saw is bound. There is one round trip fewer.
   A failed proof costs a 1 s delay on that connection. After 30 failures in a minute, failed proofs get `RateLimited`.
   A correct proof is never delayed.
2. **Script binding mechanics.** The script word in the stored command is rewritten to `"${KEYGENT_SCRIPT_<n>}"` at grant time.
   At run time that variable points at the private copy: a Linux memfd as `/dev/fd/N`, or on macOS a 0600/0700 file in the
   owner-only run dir, removed at run end and swept at broker start.
   - `./x.sh` (a project-local file with a shebang) execs the copy directly, so the kernel runs its shebang. The resolved
     shebang interpreter is pinned and re-checked like any program.
   - `source x` / `. x` are bound too.
   - A project-local file *without* a shebang (a compiled binary) is pinned by hash and is not bound as a script.
   - **Consequence:** an interpreter sees the copy's path, not the original. Python's `sys.path[0]` and Node's `__dirname`
     point at the run dir, so imports relative to the script's own directory break. Imports relative to the cwd still work.
     The spec ("passed to the interpreter") implies this. It needs a decision before release: either document it, or bind
     scripts by fd while keeping the original path visible.
3. **Memfd inheritance.** Bindings are created `MFD_CLOEXEC`. Only the run's own child clears the flag, in `pre_exec`, so
   concurrent runs never inherit each other's bindings.
4. **Containment.** Each child gets:
   - `setsid`
   - on Linux, `PR_SET_PDEATHSIG(SIGKILL)` plus a broker-wide `PR_SET_CHILD_SUBREAPER`
   - signal mask cleared, and `RLIMIT_CORE` restored to its pre-hardening value
   At run end, after a limit, or on client disconnect, the broker kills the process group and then every pid whose session id
   is the run's (ADR 0009 approach, both OSes). Seal kills every active run. A child that calls `setsid()` itself escapes;
   this is best effort, as documented.
5. **Output cap: spec conflict.** §4.1 says foreground output is "truncated with a one-line notice". §5.7 and ERRORS.md say
   a run killed by the runtime *or output* cap exits 74. **Built:** kill and exit 74 (the §5.7/ERRORS reading), because
   silent truncation would leave the agent with partial output and a misleading exit code. **SPEC §4.1 needs a one-line fix.**
6. **`--max-runtime` minimum.** Any value from 1 s to 4 h is accepted (whole minutes are shown, rounded up). The 1 min floor
   implied by the usage text bought nothing and made limit tests take minutes.
7. **Approval wait.** Phase 2 has no native prompt, so "90 s from when the prompt is shown" doesn't apply yet. Only the
   5 min queue lifetime is enforced. An approved grant gets a fresh 5 min to be consumed. Denied and consumed grants
   stay visible until they expire, so a waiting `run` learns the outcome. Total grants are capped at 64.
8. **Connection classes.** `control` is limited to Seal/Status/Deny (§4.1), so `ls` now uses the `run` class. Not yet
   enforced: the 2 s deadline for a reserved `auth` connection and the one-reserved-connection-per-PID rule. They land with
   the hook client (Phase 3), where they matter.
9. **Child env.** Built from PATH (captured at unseal), HOME/USER/LOGNAME (passwd), TMPDIR, `__CF_USER_TEXT_ENCODING`
   (macOS), `TERM=dumb`, `NO_COLOR=1`, `PAGER=cat`, `GIT_PAGER=cat` and `KEYGENT_RUN_ID`.
   **Gap vs PLATFORMS:** `LANG`/`LC_*`/`TZ` aren't captured at unseal yet, so children run in the C locale. Proposal: add
   them to the unseal handoff (it already carries PATH) in M4.
10. **Bound vs unbound.** No per-tool grammars ship in Phase 2, so every approved run is unbound: the warning is shown and
    `--remember` is refused (`NoRemember`, exit 64). This is the conservative reading of "anything not proven bound is
    unbound".
11. **Error relay.** The broker sends the canonical `keygent:` line with a protocol code: `RUN_LIMIT` = 11 is new, and
    APPROVAL_DENIED, POLICY_DENIED and BAD_REQUEST are reused. The client re-checks that the line is shaped like one of
    ours (prefix, ≤ 120 chars, no control characters) before printing it, and maps the code to the exit code.

## Consequences

- SPEC §4.1 needs the output-cap wording fixed (item 5). Decide item 2 before release.
- Still to do: the passphrase prompt in `approve` doesn't yet print the resolved binary path and signature status
  (§5.5.2 "Channels"). That's tracked for M4 together with the audit chain, which `run` must also write before it executes
  (§5.7 step 7).
