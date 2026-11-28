# Data formats (SPEC v6)

Concrete schemas for everything keygent reads or writes. Code, golden tests and fuzzers follow this file. Changes need an ADR and a
format-version bump where marked.

## 1. `vault.kgt` (binary, little-endian, format version 1)

```
offset  size  field
0       4     magic "KGNT"
4       2     format_version = 1
6       16    vault_uuid
22      8     generation (u64)
30      1     slot_count (1..=8)
31      …     slots[slot_count]: { u8 kind (1=passphrase, 2=recovery, 3=prf, 4=os_uv), 16 B slot_id,
                                   u8 kdf_id (0=none, 1=Argon2id), u32 kdf_m_kib (≤ 262_144), u8 kdf_t (≤ 10), u8 kdf_p (≤ 8),
                                   16 B kdf_salt, 24 B nonce, 48 B wrapped_dek (32 + 16 tag) }      # 112 B per slot
…       32    header_mac = HMAC-SHA256(K_hdr, bytes[0 .. start_of_header_mac])
…       4     index_len (u32)   …  24 B nonce   …  index_ciphertext (AEAD, AAD = uuid ‖ "index" ‖ generation)
…       4     entry_count (u32)
…       …     entries[]: { u8 handle_len, handle (ASCII), u32 version, 24 B nonce, u32 ct_len, ciphertext
                           (AEAD, AAD = uuid ‖ handle ‖ version) }
```

Slot AAD = `SHA-256(enc(magic) ‖ enc(format_version) ‖ enc(vault_uuid) ‖ enc(kind) ‖ enc(slot_id) ‖ enc(kdf_id) ‖ enc(kdf_m) ‖ enc(kdf_t)
‖ enc(kdf_p) ‖ enc(kdf_salt))`. It **excludes `generation`**, so broker writes never need to re-wrap slots. `generation` and the slot list are
authenticated by `header_mac`. Each slot has its own KDF params and salt, so `passwd` rotates only the passphrase slot's salt. Unknown slot
kinds are preserved but not used. KEK derivations and HKDF labels are in SPEC §5.2.

**Encoding rule for every hash, MAC and challenge input** (grant key, passkey challenges, audit MAC, slot AAD): each field is encoded
as `u32 length (LE) ‖ bytes`, then concatenated. Never plain concatenation.
Readers refuse `format_version` > supported and any field outside its cap **before** running the KDF or allocating:
`index_len` ≤ 16 MiB, `entry_count` ≤ 1 000, each `ct_len` ≤ 64 KiB + 16, `handle_len` ≤ 255, and every length ≤ the remaining file size.
After decrypting the index: an entry's `version` **must equal** the index's version for that handle (an older entry replayed from `.prev`
or a backup is rejected), and entries whose handle is not in the index are **ignored and dropped on the next write**.

Entry AAD and index AAD use the length-prefixed encoding below: `enc(uuid) ‖ enc(handle) ‖ enc(u32 version)` and
`enc(uuid) ‖ enc("index") ‖ enc(u64 generation)`.

## 2. Encrypted index (plaintext form, canonical TLV; versioned by `index_version`)

**TLV byte rules** (index plaintext and broker protocol payloads):
- Record = `u16 tag ‖ u32 len ‖ value` (index: little-endian; protocol: big-endian, per ADR 0004).
- Value types are fixed per tag: `u8/u16/u32/u64` (fixed width), `bytes`, `utf8` (validated), `bool` (one byte, 0/1), `struct` (value is a
  nested TLV sequence), `list` (the same tag repeated, in order).
- Canonical form: tags in ascending order, a non-list tag appears at most once, unknown tags are rejected (index) or closed with an error (protocol).
  Depth ≤ 4, total ≤ 16 MiB.
- Tag numbers live in `src/proto/tags.rs` and `tests/golden/tlv/` (golden byte vectors for every struct), created in Phase 1. A tag number is never reused.

| Field | Type | Notes |
|---|---|---|
| `index_version` | u16 | starts at 1 |
| `handles[]` | list | see below |
| `trusted_manifests[]` | `{ canonical_path, sha256, trusted_at }` | |
| `passkeys[]` | `{ credential_id, cose_pubkey (ES256), sign_count, label, created_at }` | |
| `shell_paths` | `{ posix?, git_bash?, pwsh? }` absolute paths | set with auth |
| `ui_binary_sha256` | 32 B | pinned at `integrate`/install with auth (ADR 0005) |
| `security_settings` | `{ ttl_max, idle, run_max_minutes, remember_enabled, default_mode }` | auth to change |
| `audit_anchor` | `{ seq, mac }` | |
| `tripwire_id` | 16 B | keystore item name |

`handles[]` entry: `{ handle, env_name, description (≤ 200 chars), binding: env|file, mode: allow|approve|confirm|deny,
allow_rules[], hosts[], created_at, rotated_at, version, previous_version_until?, exposed: bool, origin: human|capture, custody?: bool }`.
`custody` (tag `0x0211`, bool, last) is optional; absent means **on** (ADR 0022). `hosts[]` (tag `0x0207`) holds the hosts the human
approved for a custody handle. `ls` entries carry `custody` as tag `0x1027`.

Tag numbers: `src/proto/tags.rs` (handles `0x02xx`, allow rules `0x03xx`, …). `previous_value` (tag `0x0210`, bytes) holds the value
replaced by the last `rotate` and is present **iff** `previous_version_until` is (ADR 0011 #3). The recovery slot uses `kdf_id 0` with
`m = t = p = 0` (ADR 0011 #4).

`allow_rules[]`: `{ exe (absolute), sha256, args[] (literal strings, "*" = one non-dash argument, or a trailing "**"), flags[]? ({name, takes_value}; required with "**"), home: "inherit"|"scratch" }`.
Per handle also: `argv: "deny"|"allow"` (default `deny`, SPEC §3.2.6). Tool config hashes for the "changed since last approval" check: `config_seen[] = { tool, path, sha256, approved_at }`.

Grants (broker memory only, never persisted): `{ grant_id (16 B), grant_key (32 B), command, dialect, cwd, handles[], executables[{path, sha256}],
scripts[{path, sha256, size}], max_runtime, unbound: bool, created_at, shown_at?, state }`.

## 3. `.keygent.toml` (project manifest) and `config/global.toml`

```toml
version = 1                       # required

[secrets]
"stripe/live" = { env = "STRIPE_API_KEY" }                     # env: required, ^[A-Z_][A-Z0-9_]{0,63}$, not reserved
"gcp/sa"      = { env = "GOOGLE_APPLICATION_CREDENTIALS", file = true }
```

Only these keys are accepted (unknown keys → error, so a typo can never silently grant something). Max 64 KiB, max 256 entries.

## 4. `config/config.toml` (UX only, plain)

```toml
version = 1
default_dialect   = "posix"         # posix | powershell
approval_channels = ["native", "console", "terminal"]   # preference order; availability still applies
notify            = true            # desktop notification when an approval waits > 5 s
log_level         = "info"          # error | warn | info | debug
console_auto_open = true
# generic detectors can only be turned OFF via `keygent edit --settings` (auth, stored in the index)
```

Security settings never live here (SPEC §5.12). Unknown keys → warning.

## 5. Audit record (`audit.jsonl`, one JSON object per line)

```json
{"v":1,"seq":1042,"ts":"2026-11-15T10:12:03Z","event":"run","handles":["stripe/live"],"decision":"approved",
 "channel":"native","cmd":"STRIPE_API_KEY={{keygent:stripe/live}} stripe customers list --limit 3","grant_key":"9f2c…",
 "exes":[{"path":"/opt/homebrew/bin/stripe","sha256":"…"}],"scripts":[],"cwd":"/Users/u/proj","exit":0,"redactions":1,"dur_ms":842,"mac":"b64…"}
```

`event` values: `unseal`, `seal`, `run`, `capture`, `grant`, `approve`, `deny`, `add`, `rotate`, `rm`, `rename`, `edit`, `trust`,
`untrust`, `reveal`, `passkey_add`, `passkey_rm`, `auth_fail`, `exposed`, `migrate`. `cmd` is the rendered template with placeholders,
always passed through the redactor. **MAC input** = `enc(prev_mac) ‖ enc(L)`, where `L` is the exact UTF-8 bytes of the line **as written**,
with the trailing `,"mac":"…"` member removed (the writer always emits `mac` last, with no whitespace). Verifiers strip that same suffix
byte-for-byte; they never re-serialize. An `epoch` record links chains across `rekey`:
`{"v":1,"seq":…,"event":"epoch","next_first_mac":"…","mac":"<old K_audit>"}`.

As built in Phase 2 (ADR 0015): `mac` and `grant_key` are lower-case hex (64 chars), not base64. The first record chains from 32 zero
bytes. `audit.anchor` lines are `<seq> <hex HMAC(K_audit, enc(seq as u64 LE) ‖ enc(mac))>`. A run writes a `run` record with
`decision:"start"` before exec (fail closed) and one with `decision:"end"|"limit"|"client_gone"`, `exit`, `redactions`, `dur_ms` after.
Not built yet: rotation, the 10-min tripwire anchor, the `rekey` epoch record.
Custody (ADR 0022): an `egress` record per (decision, host, handles) of a run, written before the run's `end` record:
`{"event":"egress","handles":["do/token"],"decision":"forwarded"|"credential_endpoint_mismatch","host":"api.digitalocean.com","requests":3}`.

## 6. Hook I/O (Claude Code adapter, per ADR 0001)

Rewrite (PreToolUse):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse",
  "updatedInput":{"command":"'/Users/u/.local/bin/keygent' run --grant 9f2c4e…","description":"<original>","timeout":240000},
  "additionalContext":"keygent: waiting for approval (Touch ID / 'keygent approve' / console)"}}
```

The `additionalContext` line is emitted only when an approval is pending, to keep the happy path at zero tokens. Prompt block, deny and
post-redaction shapes follow ADR 0001. Golden files live in `tests/golden/hooks/`.

## 7. Broker protocol

ADR 0004 (TLV frames). TLV tag registry: `tests/golden/protocol/tags.md` (created in Phase 2).

## 8. Recovery key display (ADR 0011 #2, proposed)

Crockford Base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. The 32-byte key is encoded MSB-first into 52 characters (4 zero pad bits),
shown in groups of 7-7-7-7-6-6-6-6, then a 2-character group with the top 10 bits of `SHA-256(enc("kg/v1/recovery-check") ‖ enc(key))`.
Example shape: `3M9W26P-9MBYXMS-T6PMYPP-QBJ2SZ9-ZXGKSH-KAWJJV-NRVWJC-F10CT0-8W`. Input ignores spaces, `-` and tabs, is
case-insensitive, and maps I/L → 1 and O → 0. Non-zero pad bits or a checksum mismatch are rejected before any vault work.
