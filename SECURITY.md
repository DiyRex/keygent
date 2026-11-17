# Security

## Reporting a vulnerability

Please use **GitHub private vulnerability reporting** (Security → Report a vulnerability) on `DiyRex/keygent`. Do not open a
public issue. Never include real secrets. Use a canary value. We aim to acknowledge within 3 business days, and to agree
on a disclosure date within 90 days.

## Supported versions

Only the latest release receives security fixes until 1.0. After 1.0, the latest minor version does.

## Security model (summary)

- The AI agent is assumed to run **as the same OS user** (ADR 0003). keygent targets accidental leaks (T1) and generic
  prompt injection (T2). An agent deliberately attacking keygent (T3) is out of scope for v1. Every known gap is listed in THREATS.md.
- **Only the broker holds plaintext.** It spawns authorized commands itself and returns only redacted output. The single
  response that carries a value (`Reveal`) needs a fresh **passphrase proof only** (never UV, never the console).
- **Authorization uses factors the agent can't fake:** the passphrase (mutual challenge-response, never transmitted), native OS
  user verification with broker-supplied text (Touch ID; Windows Hello only if per-request text is proven in Phase 0), and passkeys on the broker-launched console. Grants are
  approved only through these channels, which the broker observes itself (ADR 0007). Claude Code's own dialog is the T1-only `confirm` mode.
- **Allow rules pin the executable** (absolute path + SHA-256), ignore the client's PATH and cwd, and exec without a shell.

## Cryptography

| Purpose | Primitive |
|---|---|
| Passphrase → KEK | Argon2id, m = 64 MiB, t = 3, p = 4 (RFC 9106), per-vault salt. Params are capped before use and upgradeable on `rekey` |
| Wrap DEK (KEK slots) | XChaCha20-Poly1305, AAD = SHA-256(length-prefixed magic, version, uuid, KDF params, salt, slot id, slot kind) — excludes `generation`; `header_mac` covers the rest |
| Encrypt entries and index | XChaCha20-Poly1305, random 24-byte nonces. Entry AAD = len-prefixed(uuid, handle, version); index AAD = len-prefixed(uuid, "index", generation); entry version must match the index |
| `rekey` | new random DEK, everything re-encrypted |
| Key separation | HKDF-SHA256 from the DEK: `K_entry`, `K_index`, `K_hdr`, `K_audit`, `K_auth`, `K_broker` |
| Header integrity, rollback | HMAC-SHA256 (`K_hdr`) over the header, including a monotonic generation counter |
| Audit log | HMAC-SHA256 chain (`K_audit`), anchored per record in `audit.anchor`, in the index, and in the keystore tripwire |
| Re-auth | mutual HMAC challenge-response. separate HKDF session keys per direction, counter nonces |
| Passkeys | WebAuthn ES256, user verification required, origin bound to the broker-launched console child |

RustCrypto crates only (`chacha20poly1305`, `argon2`, `hkdf`, `sha2`, `hmac`, `p256`, `zeroize`, `getrandom`). No custom
crypto. Constant-time comparisons for MACs and tokens.

## Process hardening (per OS details in PLATFORMS.md)

- Secret material in a locked arena, plus a zero-on-free allocator for everything else (`mlockall` too on Linux). Secret types have no `Debug`/`Display`.
- No core dumps or debugger attach: `PR_SET_DUMPABLE=0` (Linux), `PT_DENY_ATTACH` + hardened runtime (macOS), WER exclusion +
  process DACL (Windows).
- Injection defenses: static musl (Linux), hardened runtime with library validation (macOS), `SetDefaultDllDirectories` and
  mitigation policies (Windows). The broker starts with a cleared environment.
- IPC is private to the user (0700 dir / owner-SID DACL), bound exclusively, and the peer identity is checked.
- Children are contained (Job Object / subreaper / process group) and killed with the run.

## Device safety

No admin/root, no services or drivers, no shell-rc edits, loopback-only listener, no outbound network, no telemetry, clean
`keygent uninstall`. See SPEC §3.3.

## Supply chain

- `cargo-deny` (advisories, licenses, bans incl. `tokio` and `openssl-sys`), `Cargo.lock` committed, `--locked` builds.
- Release workflow: actions pinned to commit SHAs, `persist-credentials: false`, least-privilege job permissions.
- Every release: SHA256SUMS signed with keyless cosign, plus build-provenance attestations. Verified automatically by `install.sh` / `install.ps1` (pinned cosign). macOS Developer ID +
  notarization and Windows Authenticode are deferred (owner decision). Weekly `cargo deny` advisory check (`security.yml`).
