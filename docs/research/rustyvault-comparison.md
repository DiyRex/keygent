# RustyVault vs keygent: what to adopt

- **Date:** 2026-11-28
- **RustyVault version:** `rusty_vault` 0.3.1, commit `4efe033ce7abf66c213422a3c35b325d45dcf8f3` (2025-10-15), source read at that commit
- **Comparison baseline:** HashiCorp Vault docs for [key rotation](https://developer.hashicorp.com/vault/docs/internals/rotation) and
  [audit devices](https://developer.hashicorp.com/vault/docs/audit)
- **Limits of this review:**
  - Statements that something is *absent* cover only the files named.
  - RustyVault was not built, so its binary size was not measured.

## Different shapes

RustyVault is a **multi-tenant network secret server**. It is a Rust port of Vault: clients hold bearer tokens, path ACLs
decide access, and **values are returned to the authorized client**.

keygent is a **single-user local broker**. Its central rule is that no request ever returns a value (SPEC §3.2.1), and its
attacker is an agent running as the same OS user (§3.1). In keygent's setting:

- A bearer token readable by that user is a T2 hole.
- Network machinery (router, mounts, HTTP, HA) costs size and buys nothing.

## What RustyVault does

| Area | RustyVault (source) |
|---|---|
| Barrier | AES-256-GCM through OpenSSL, random 12-byte nonce. Header `[0,0,0][epoch=1][ver][nonce]`. v2 binds the storage path as AAD; v1 has no AAD (`storage/barrier_aes_gcm.rs`) |
| Key rotation | None. The epoch is fixed at 1, so there is no keyring (Vault has keyring terms) |
| Unseal | Shamir shares of the KEK in GF(256) via lookup tables (not constant time), `rand::thread_rng` (`core.rs`, `shamir.rs`) |
| Storage | One JSON file per key. Writes are not atomic and use the default file mode (`storage/physical/file.rs`). Also SQL backends |
| Routing | Mount table with a per-entry HMAC, radix-trie router, per-mount `BarrierView` prefix |
| Auth | UUID tokens stored under salted SHA-256, parent/child trees, `num_uses`, root token |
| Policy | Path ACL with a capability bitmap, deny overrides, `*`/`+` globs, parameter allow/deny lists |
| Leases | Persisted, with a 200 ms priority-queue revoker. Restored on unseal |
| Audit | No audit device found at this commit, although the README claims one. Vault HMACs request fields, and Vault fails closed |
| Memory | `zeroize` only. No mlock in `server.rs` |
| Crypto and size | OpenSSL/Tongsuo, actix + tokio + rustls. Far above 2 MB (an estimate, not measured) |

## Gap table

| Pattern | keygent today | Verdict |
|---|---|---|
| Barrier / AEAD with AAD | Entry AAD binds the uuid, handle and version (FORMATS §1). That is stronger than RustyVault's path-only AAD | Keep. The "swap entries" test stays |
| Keyring terms / online rotate | `rekey` re-encrypts everything, with no secret re-entry | **Not adopted.** XChaCha's 192-bit nonce removes the nonce-count reason. A keyring under the same root doesn't help after a compromise, which is the only reason keygent rekeys |
| HMAC'd config tables | `header_mac`, AEAD index | Already covered |
| Shamir | Phase 6 | **Adopt later, narrowly.** Split only the recovery key, and combine the shares in the CLI. Needs an ADR exception to "no custom crypto" (no RustCrypto crate). Must be constant time and use `getrandom`. Do not port RustyVault's code |
| Audit confidentiality | v1 stores the command and cwd in clear | **Adopted** → [ADR 0018](../adr/0018-audit-log-v2.md) §2 (encrypted `x` field) |
| Fail-closed audit | Already built | Already covered |
| Leases / revoker | Grants are single-use, in memory, with deadlines. Seal wipes them | Nothing to add locally. Phase 7 backend leases already follow restore-on-unseal (ADR 0016 A5) |
| Revoke-by-principal | At run time, the broker re-checks each handle's existence and mode (`run_grant`), so `rm` or a tighten-to-deny blocks pending runs | **Adopt the rest:** a tightening edit, `untrust` or `exposed` also drops approved-but-unused grants and `--remember` entries for that handle. Leak test: approve → deny → retry must not run |
| Bearer tokens | None. Mutual-auth proofs and per-action UV | **Not adopted** (T2) |
| Path-glob ACLs | Per-handle modes + pinned allow rules | **Not adopted.** Globs widen access silently. Policy review stays with `rule ls`, `edit` diffs and approval rendering (Cedar skipped, ADR 0020) |
| Mounts / router / HTTP / OpenSSL | — | **Not adopted.** Size and multi-tenancy, no T1/T2 value |
| Plaintext hygiene | Locked arena, zero-on-free, no dumps, `Debug` blocked | keygent is stronger here |
