# ADR 0011 — Phase 1 implementation choices where the SPEC was open or needed a fallback

- **Status:** proposed (for Phase 1 review)
- **Date:** 2026-11-16
- **Verified against:** keygent Phase 1 code (`phase-1-vault-core`), rustc 1.100.0, macOS 26.6.2, Linux container

## Context

Building the vault core needed concrete answers the SPEC v6 leaves open, plus one SPEC §15 fallback. Each item below is implemented
and tested; this ADR asks the reviewer to accept or change them.

## Decisions (proposed)

1. **Device pepper and rollback tripwire: owner-only files in the state dir on every OS** (`state/device.key`,
   `state/tripwire-<id>`). This is the SPEC §15 fallback. The OS keystores (macOS Keychain with a per-app ACL, DPAPI, Secret Service via
   `secret-tool`) need the keystore spike first. **Weaker than SPEC on macOS** (no per-app ACL; equals a T2 copy). `doctor` (Phase 3) must say so.
2. **Recovery key encoding** (SPEC §5.2 said "Base32, 8 groups + 2-char checksum"): Crockford Base32, 52 data chars in groups
   7-7-7-7-6-6-6-6, checksum = top 10 bits of `SHA-256(enc("kg/v1/recovery-check") ‖ enc(key))`. Input accepts lower case, spaces, and
   I/L→1, O→0. Recorded in FORMATS §8.
3. **Previous values (24 h after `rotate`) live in the encrypted index** as handle tag `0x0210 previous_value`, paired with
   `previous_version_until`. SPEC §5.2 lists "previous values for 24 h" in the index; FORMATS §2 didn't name the field. Entries keep the
   strict "entry version = index version" rule, so a previous value can never be replayed as an entry.
4. **Recovery slot** uses `kdf_id = 0` with `m = t = p = 0` (the parser rejects any other combination for `kdf_id 0`).
5. **Strength estimator separator rule** (stricter than the SPEC text): one `- _ . , space` right after a pattern costs 1 bit. Without it,
   four EFF words joined by `-` scored 71.5 bits and passed the 70-bit passphrase floor, contradicting SPEC §5.3 step 4 ("≥ 5 random words").
   Golden vectors still hold: `Passw0rd!2024` = 28.0, `john.smith1985` = 35.9, random 32-char base62 = 190.5 (measured).
6. **Only the first 256 bytes are scored** by the estimator (bounds the O(n²) segmentation; extra bytes only add strength).
7. **`ls` exits 78 in Phase 1** (always sealed: there is no broker yet), exactly as SPEC §5.1 specifies. `verify` lists handles for humans.
8. **Lock file** `vault.kgt.lock` next to the vault (the vault itself is replaced by rename, so it can't carry the lock).
9. **Test isolation:** besides `KEYGENT_TEST_ROOT`, the `test-profile` feature honours `KEYGENT_TEST_FAST_KDF` (Argon2id m=64 KiB, t=1)
   and routes the console to stdin/stderr. Both are compiled out of release builds; preflight greps the release binary.
10. **Secret memory in Phase 1** is zeroize-on-drop heap buffers. The locked arena and zero-on-free allocator are Phase 2 (ROADMAP), as is
    the broker-side "factor changes ask running brokers to seal" step (no broker exists yet).
11. **Windows** primitives fail closed with `Unsupported` (ADR 0010); nothing silently no-ops.

## Consequences

- Accepting 1 means macOS vault copies are protected by the pepper only against off-box copies until the Keychain backend lands.
- 2–4 are format details: changing them after release needs a format/index version bump.
- On acceptance, add SPEC §17 rows and fold 2–4 into FORMATS permanently (already drafted there as §8 and the §2 tag note).
