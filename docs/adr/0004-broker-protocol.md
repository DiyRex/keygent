# ADR 0004 — Broker IPC protocol

- **Status:** accepted (SPEC v6). Implemented in Phase 2.
- **Date:** 2026-11-15
- **Verified against:** design only. Golden and fuzz tests pin it once implemented.

## Context

Every client (CLI, `run`, hooks, `keygent-ui`) talks to the broker over a Unix socket or a Windows named pipe at a fixed per-user
location (SPEC §5.4). Any same-user process can connect (ADR 0003). The protocol itself must therefore enforce the plaintext invariant,
be small enough to fuzz completely, and behave identically on all three OSes.

## Decision

### Transport and framing

- One request per connection, except `Run`/`Capture` (stream until `Exit`) and `AwaitGrant` (blocks until decided).
- Frame: `u32 length (BE) ‖ u8 protocol version (=1) ‖ u8 type ‖ payload`. **Max 1 MiB.** Output chunks ≤ 64 KiB.
- Payload: a flat TLV list (`u16 tag ‖ u32 len ‖ bytes`). Unknown or duplicate tags are rejected. No serde on this path.
- Timeouts: 5 s for a complete request frame, 30 s idle on non-streaming connections. Limits: 32 connections (**5 reserved**: 4 for the
  `auth`/`control` classes, 1 for hook `MatchPrompt`), 8 runs, 16 pending grants deduplicated by grant key (SPEC §4.1).
- Byte order: protocol frames are big-endian (network order). The vault file is little-endian (FORMATS). Both are fixed and tested.
- Additional requests: `Check{cmd, dialect, cwd}` (none → decision explanation, no grant created; called by `hook pre` for every
  Bash/PowerShell command while unsealed), `Import{entry}` (**one entry per frame**, all within one `Auth` session; the CLI streams them)
  and `MarkExposed{handle}` (no auth, can only add exposure, **rate-limited to 1/min per handle**, and only notifies the human).
- **Client-side broker verification** (all clients): peer PID → executable path + hash = installed keygent, and that PID holds `broker.lock`
  (SPEC §5.4). Otherwise fail closed.
- Auth failures: a 1 s delay **on the failing connection only**, and a global cap of 30/min → `RateLimited`. A correct proof is never delayed.
- **Version lock:** the build id must match, otherwise `keygent: broker is an older version — run 'keygent seal' then 'keygent unseal'`.

### Handshake (every connection)

1. Client → `Hello{build_id, nc (32 B)}`
2. Broker → `Welcome{build_id, nb (32 B), proof_b = HMAC(K_broker, enc("kg/v1/broker") ‖ enc(nc) ‖ enc(nb))}`
3. Clients that unwrapped the DEK locally (auth flows) **must** verify `proof_b` before sending anything else. Clients without auth (`run`,
   hooks) can't verify it, and send nothing secret.

### Requests

| Type | Auth | Returns | Notes |
|---|---|---|---|
| `Status`, `List`, `Pending`, `AuditRead` | none | metadata | never values |
| `Run{grant}` / `Run{cmd, dialect, cwd, max_runtime}` | policy | stream `Stdout`/`Stderr` (redacted), `Exit` | hook form carries **only the grant id**, and the broker runs the stored command. The direct form creates a grant first. The client env is **not** sent. **There is no client stdin frame**: the child's stdin is `/dev/null` unless the stored command supplies it. Client → `Signal` only. Client EOF kills the tree |
| `Capture{handle, cmd}` | policy | `Stored{handle}` | create-only. Overwriting → `NeedsAuth` |
| `Redact{bytes}` | none | redacted bytes | chunked by the client with carry-over. 64 MiB/s |
| `MatchPrompt{text}` | none | `{matched: bool, vault_match: bool}` | **never handle names**. 20/s, with one reserved connection. A vault match marks the handles exposed broker-side. Prompts over 1 MiB are sent in chunks that **overlap by 64 KiB** (the max secret length), and the broker matches across them |
| `UvAuth{action, canonical_params_hash}` | — | `Authed` (one action) | only for the short actions in SPEC §5.5.1. The broker renders the OS prompt text itself |
| `GrantCreate{cmd, dialect, cwd}` | none | `grant_id` (128-bit), expiry | the broker computes the grant key itself (command, dialect, cwd, handles, resolved program, **script file hashes**), renders it with `render_for_approval()`, and raises the native prompt only if it qualifies (SPEC §5.5.2) |
| `AwaitGrant{grant_id}` | none | approved / denied / expired | used by `run` |
| `Auth{proof_c = HMAC(K_auth, enc("kg/v1/client") ‖ enc(nb) ‖ enc(nc) ‖ enc(H(request)))}` | — | `Authed` | 1 s delay per failure, no auto-seal |
| `Approve{grant_id, grant_key_hash}`, `AddValue`, `Rotate`, `Remove`, `Rename`, `EditPolicy{displayed_diff_hash}`, `Trust{displayed_content_hash}`, `PasskeyAdd`, `PasskeyRemove`, `Rekey`, `SetShellPaths` | `Auth` (the request hash, including the displayed hashes, is bound into `proof_c`) | `Ok` | values only inside `Sealed{…}`. The broker refuses `Trust`/`EditPolicy` whose displayed hash doesn't match the current content |
| `Untrust`, `Deny{grant_id \| all}`, `Seal` | none | `Ok` | can only reduce access |
| `UiLaunch` | none | port | the broker spawns `keygent-ui` and binds the origin to that child |
| `PasskeyChallenge{action, target, params_hash}` / `PasskeyVerify{assertion}` | session / — | challenge / action result | console actions only (ADR 0005) |
| `Reveal{handle}` | `Auth` (passphrase proof only) | `Sealed{value}` | **the only response that carries plaintext**, and only under the session key |

### Session encryption

Two keys, one per direction: `K_c2b = HKDF(K_auth, salt = enc(nc) ‖ enc(nb), info = "kg/v1/session/c2b")` and `K_b2c` (`…/b2c`).
`Sealed` frames use XChaCha20-Poly1305 with nonce = 16 zero bytes ‖ u64 counter (starting at 0 per direction, strictly increasing, and any
regression or gap is rejected), with the frame header as AAD. A relay or squatter sees only ciphertext.

`Hello` declares a connection class (`hook`, `run`, `auth`, `control`, `ui`) used for the reserved-connection pool (SPEC §4.1). A connection
that declares `auth`/`control` but sends anything else is closed.

### Errors

`Err{code, message}`, where the message is one line ≤ 120 chars, starts with `keygent:` and names the next action. Exit codes: `ApprovalDenied` 75,
`NotTrusted` 76, `PolicyDenied` 77, `Sealed` 78, `VersionMismatch`/`Internal`/`RateLimited`/`TooLarge` 79, `NeedsAuth` 1 (human-facing commands and `capture` overwrite only; never a plain `run`).
The full catalog is [ERRORS.md](../ERRORS.md). **No error echoes request contents or values.**

## Consequences

- About 300 lines of TLV parsing with its own fuzz target. Every limit has a test.
- The CLI briefly holds the DEK in locked memory during auth flows.
- Protocol changes bump the version byte and need an ADR.
