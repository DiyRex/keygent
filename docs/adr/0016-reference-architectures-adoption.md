# ADR 0016: Adopt patterns from CNCF and Linux Foundation reference architectures

- **Status:** proposed
- **Date:** 2026-11-17
- **Verified against:** [docs/research/cncf-lf-reference-architectures.md](../research/cncf-lf-reference-architectures.md)
  (sources fetched 2026-11-17; CB4A, tokenizer, OpenShell provider and driver claims re-checked against the primary
  source)

## Context

Several CNCF, Linux Foundation and IETF efforts solve neighbouring problems:

- **Egress credential injection:** CB4A, agentgateway, Envoy, OpenShell, Fly.io tokenizer.
- **Hook-level policy for coding agents:** Prempti / Falco.
- **Runtime governance and approval workflows:** OpenShell, Cedar.
- **Secret backends:** OpenBao.

None covers keygent's core case: local CLI children, output redaction, and approval bound to command, program and
script hashes.

Some of their mechanisms close keygent's known gaps:

- the T3 child-env residual;
- long-lived static values;
- hand-coded policy that can't be reviewed outside the code;
- no SIEM-friendly audit format;
- coexistence with other agent hooks.

Hard constraints:

- a binary of 2 MB or less;
- RustCrypto only;
- no async runtime;
- only the broker holds plaintext, and no request returns a value;
- the agent is the same OS user (ADR 0003).

## Decisions

### Adopt (by phase)

| # | Pattern (source) | keygent design | Phase | Cost |
|---|---|---|---|---|
| A1 | Placeholder custody (OpenShell, Deno, tokenizer, CB4A Model A) | Egress proxy redesign. See "Egress design" below | 6 | TLS client size: **needs a spike** |
| A2 | PDP/CDP split (CB4A §2.1) | `policy/` (no plaintext) compiles a typed *egress grant*: handle, hosts, header slot, format, methods. The broker proxy only enforces it and makes no new decisions. This fits the existing plaintext boundary | 6 | none |
| A3 | Fail-closed audit before issuing (CB4A) | Already true for runs, CLI writes and `reveal` (ADR 0015). Extend to every proxy injection | 6 | none |
| A4 | Model B minting (CB4A recommended; tokenizer `github_app` / `client_credentials`) | New handle kind `minted`. A long-lived *root* (GitHub App key, OAuth client secret) stays in the broker. Each run gets a short-lived token from it, revoked or expired at run end. Shrinks leak impact even with env injection | 7 | small (HTTP calls go through the egress or backend transport) |
| A5 | OpenBao leases plus response wrapping | `SecretBackend` trait; see "Backend design" below. First backend: OpenBao KV v2, then dynamic database creds | 7 | about +20–40 KB *estimate* |
| A6 | Prempti coexistence | Chain composer recognises Prempti; see "Hook coexistence" below | 3 | none |
| A7 | Prempti sensitive paths plus canonical matching | Add these to keygent's default deny set: `.envrc`, `.env.*`, `.netrc`, `.npmrc`, `.pypirc`, `credentials.json`, `token.json`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.azure`, other agents' OAuth files. Match on canonical paths **and** the access name | 3 | none |
| A8 | Policy as reviewable data (Cedar, OpenShell YAML↔Cedar parity) | Model policy internally as principal / action / resource / context (below). Add `keygent policy export --format json\|falco`, which only generates text. **Cedar dropped by owner decision ([ADR 0020](0020-cedar-policy.md))** | 3–4 | small |
| A9 | Approval state machine (OpenShell Policy Advisor) | States below. Every record carries the actor, an `auto` flag and the source | 4 (console), M5 (core states) | small |
| A10 | Staged rules (`@enforcement("audit")`) | An allow rule may be `enforcement = audit`. It logs "would have run silently" but still asks for approval, until promoted with auth | 3 | small |
| A11 | Binary identity on the open handle (OpenShell) | Linux already hashes and execs through one fd (ADR 0015). macOS: open, hash, keep the handle, re-check dev, inode, size and ctime right before exec. This narrows (doesn't close) the T2 residual | M5 / 3 | small |
| A12 | Audit export (OCSF 1.8, Prempti field names) | `keygent audit --export ocsf\|coding-agent` writes JSONL from the HMAC chain. Uses `agent.*` / `tool.*` names plus a `keygent.*` namespace (handle, grant_id, decision, rule_id, approval_mode, redaction count). **Never command text or values.** The HMAC chain stays authoritative | 3 | small |
| A13 | Unprivileged child confinement (OpenShell, Codex) | Optional per-rule confinement of a secret-holding child: Landlock plus seccomp on Linux, Seatbelt on macOS, restricted token or Job Object on Windows. Read-only outside the cwd; network limited to the handle's `hosts`. Defense in depth, never the gate | 6 | tens of KB *estimate* |

### Egress design (A1–A3)

1. **The child gets a placeholder, never the value.**
   - Format: `KEYGENT_PH_<base32 128-bit>`, minted per run and per handle, valid only in that run's proxy.
   - An optional per-handle prefix template (for example `sk_live_`) for SDK format checks.
   - The redactor also knows the placeholders.
2. **Mode R (default), reverse proxy / base URL, no TLS interception.**
   - The child gets e.g. `*_BASE_URL=http://127.0.0.1:<port>/<run-token>/…`.
   - The broker dials `https://<bound host>` itself and verifies the certificate against system roots.
3. **Mode C (opt-in per handle), CONNECT with interception.**
   - Ephemeral per-run CA, held only in broker memory, X.509 **name-constrained to the bound hosts**, valid for minutes.
   - Trust is passed by env vars only: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`,
     `CURL_CA_BUNDLE`, plus `NODE_USE_ENV_PROXY=1`. The bundle includes the system roots.
   - **Never install it in an OS trust store** (SPEC §3.3).
   - Require CONNECT host = SNI = `Host`. tokenizer refuses CONNECT entirely, which is why this mode is opt-in.
4. **Substitution scope.**
   - Substitute only in declared header slots (default `Authorization: Bearer %s` or `x-api-key`). Query parameters are
     opt-in.
   - **Never in bodies.** A writable API on an allowed host could reflect a body.
   - Substitute only where the placeholder appears; never blind-inject.
5. **Host binding.**
   - Exact normalised host (lowercase, IDNA, no trailing dot). Wildcards only as the leftmost label.
   - https on port 443 only.
   - The upstream comes from the grant, never from `Host`.
   - Resolve DNS in the broker and refuse private, loopback and link-local addresses unless the handle opts in.
   - Follow no redirects.
   - A placeholder seen for an unbound host means **403, audited as an exfiltration attempt**
     (`credential_endpoint_mismatch`).
6. **Responses** pass back through the redactor, which replaces the value with the placeholder.
7. **Lifecycle.**
   - One proxy per run, on `127.0.0.1:0`, with a random run token.
   - Thread per connection, blocking I/O.
   - Dies with the run, the seal or the grant TTL.
8. **Not covered (fail safe, not functional):** non-HTTP protocols, client-side signing (unless re-signed), pinning or
   mTLS, local-use keys, HTTP/3, clients that ignore proxy or CA env. Those handles keep env injection, labelled T3
   residual.
9. **Remaining residual (document it as narrowed, not closed):** same-user code can *use* a handle on its bound hosts
   while the run lasts. It can't *see* the value. T3 goes from "steal" to "use within scope and time".

### Backend design (A4–A5)

1. **Transport.** Plain HTTP/1.1 over the Unix socket of a local `bao proxy`.
   - The broker launches the proxy from a **pinned path + SHA-256**, with a generated config.
   - The proxy owns TLS to the server.
   - Required config: no auto-auth, no sinks, no cache, no `use_auto_auth_token`.
   - keygent sends `X-Vault-Token` from the locked arena on each request.
   - No rustls in keygent.
2. **Identity.** AppRole, with the `secret_id` **stored as a keygent vault secret**, so only an unsealed broker can log
   in. The backend can't tell the agent from the human on the same uid (SPIFFE can't either).
   - Bootstrap: a response-wrapped `secret_id`. `keygent backend add` checks the creation path with
     `sys/wrapping/lookup`, then unwraps after a passphrase proof. "Already unwrapped" means tampering.
3. **Trait** (blocking; only `vault/` and `broker/` call `resolve`/`get`):
   - `id()`
   - `caps()`
   - `login(HumanProof)`
   - `get(RemoteRef, Requester{grant_id, program_sha, project}) -> Fetched{value: Secret, lease: Option<Lease>, version}`
   - `renew(Lease)`
   - `revoke(Lease)` (idempotent)
   - `rotate(RemoteRef, new, cas)`
   - `metadata(RemoteRef)` (no values)
   - `logout()`

   `Requester` lets a backend authorize independently, like the Agent Substrate provider.
4. **Leases bound to runs.**
   - Each run of a dynamic ref gets a new lease with TTL ≤ `max_runtime + 60 s`.
   - The lease **id** is written to a journal before spawn. The value goes into the arena and the redactor.
   - The lease is revoked when the child exits. Orphans are revoked at the next unseal.
   - A failed revoke is retried, audited as `revoke_failed`, and shown in `doctor`.
5. **Caching.** Plaintext lives only in the arena. KV values may be cached until seal, keyed by version. Dynamic values
   are never shared across runs.
6. **Failures fail closed.** Unreachable backend, expired token, unparseable reply, or an OpenBao audit-device outage all
   refuse the run with a one-line `keygent:` error.
7. **Audit linkage.** The chain record holds the grant id, backend id, path, version, OpenBao `request_id`, `lease_id`
   and token accessor. Never values.
8. **SOPS.** `keygent import --sops <file>` runs a pinned `sops decrypt` and pipes its output into the broker the way
   `capture` does. The output never reaches the agent.

### Hook coexistence (A6)

- Prempti only answers PreToolUse, never returns `updatedInput`, and never touches outputs. Claude Code merges parallel
  decisions as deny > ask > allow. So **run Prempti in parallel; don't chain it.**
  - keygent's rewrite is the only `updatedInput`.
  - Prempti sees the original command with placeholders and no plaintext.
  - Chaining would put Prempti's 5 s fail-closed timeout inside keygent's 30 ms budget.
- `premptictl` re-adds its hook on every start. `doctor` and `integrate` detect a Prempti entry, accept it as a known
  parallel PreToolUse-only observer, and never treat a Prempti `allow` as approval. Its channel is unauthenticated, so it
  counts as T1 at most.
- Add canary leak tests to check that Prempti's "secret env var" and "encoded payload" rules don't fire on keygent
  rewrites (`run --grant <id>`).

### Policy model (A8–A10)

- **Principal:** `Agent::Session{kind, session_id}` or `Human`.
- **Action:** `inject`, `capture`, `reveal`, `rotate`, `approve`, `trust_manifest`, `egress`.
- **Resource:** `Secret::"<handle>"` in `Project::"<root-hash>"`.
- **Context:**
  - `program{path, sha256}`
  - `argv` already tokenized into `{subcommand, flags: set, positionals}`, because Cedar has sets, not lists
  - `cwd`
  - `script_hashes`
  - `max_runtime`
  - `approval{kind: none|terminal|uv|passkey, age}`
  - `tier`
- **Approval states:**
  `Proposed → Pending(render_hash) → Approved{once|session|rule} | Denied{reason} | Expired → Consumed | Revoked`.
  - The requester can never approve.
  - Proposing never changes policy.
  - Promoting a rule to auto-approval needs a hand-coded "does not broaden" check, the keygent version of
    `credential_reach_expansion`.

### Rejected

| Option | Why |
|---|---|
| Embedding the Cedar engine (`cedar-policy`) | about +1.5–3 MB *estimate*, over the 2 MB cap. Export text instead |
| rustls in the core binary *before* a measured spike | about 1.4–1.7 MB for the client alone. Decided by the Phase 6 spike (A1) |
| SPIFFE/SPIRE for agent identity | Same uid and same binary give the same SVID. Adds a daemon for no T1/T2 gain |
| OpenBao Agent `exec` mode / `use_auto_auth_token` | Bypasses redaction and hands tokens to any same-user process |
| Copying Prempti's unauthenticated loopback verdict channel | Forgeable by any local process |
| keygent as an OpenShell credential driver **in core** | `ResolvedCredential.value` returns plaintext, which breaks "no request returns a value". It also needs gRPC (tonic/prost, over 1 MB *estimate*). **Deferred** (below) |

### Deferred

**OpenShell credential driver.** Possible only as a separate `keygent-openshell` binary or feature, after an ADR plus a
SPEC §17 row creating a "pinned peer gateway" consumer class:

- T1 only;
- the peer verified by path and SHA-256 like allow-rule binaries;
- per-handle `export_to` opt-in;
- first-bind human approval;
- every resolve audited.

Defensible only because OpenShell puts the agent inside a kernel or VM boundary.

**DPoP.** Needs P-256 **signing**, but SPEC allows `p256` for verification only. That needs its own ADR in Phase 6.

## Consequences

**Spec changes to make when these phases start:**

- **§5.13 egress:** rewrite with placeholder custody, modes R and C, host binding, no bodies, 403 plus audit on
  mismatch.
- **§4 crypto:** P-256 signing and a name-constrained CA, if A1 mode C or DPoP are adopted.
- **§6:** policy export.
- **§9:** audit export formats.
- **§17:** row for the pinned peer gateway, if pursued.
- **THREATS:** T3 narrowed from "steal" to "scoped use"; new row for egress mismatch / exfiltration attempts.

**Spikes needed before committing:**

1. TLS client size (rustls ring vs rustls-rustcrypto vs OS TLS) and a cargo-feature budget.
2. A CA env coverage matrix: Go, Node, Python, Java, .NET, curl, git, on 3 OSes.
3. A live `bao proxy` check of the lease API bodies and of the Proxy API's deprecation.

**Roadmap:** items added to Phases 3, 6 and 7, marked "(ADR 0016, proposed)".

**Not changed:** Phase 2 scope. Only A9's core states and A11 are candidates for M5, and only if cheap.
