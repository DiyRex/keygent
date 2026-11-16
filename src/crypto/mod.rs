//! Thin wrappers over the RustCrypto crates (SPEC §4, §5.2). No custom primitives.
//!
//! Invariants upheld here:
//! - `Secret`, `Dek`, `Kek` and `Subkey` have `pub(crate)` constructors, zeroize on drop, and implement neither
//!   `Debug`, `Display`, `Clone` nor any serialization trait (SPEC §4.2). Only `crypto/`, `vault/`, `broker/`,
//!   `redact/` and `cli/` (auth flows) may name them; `scripts/preflight.sh` enforces that.
//! - Every hash/MAC/AAD/KDF input with more than one field uses `enc()` (FORMATS §1): `u32 LE length ‖ bytes` per field.
//! - KDF parameters are capped before any work (FORMATS §1).
//! - MAC comparisons are constant-time (`hmac::Mac::verify_slice`).

use crate::error::{Error, Result};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hmac::Mac;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SALT_LEN: usize = 16;

/// KDF caps (FORMATS §1). Checked before any allocation or KDF work.
pub const KDF_M_MAX_KIB: u32 = 262_144;
pub const KDF_T_MAX: u8 = 10;
pub const KDF_P_MAX: u8 = 8;

/// Default passphrase-slot parameters (SPEC §5.2): Argon2id m=64 MiB, t=3, p=4.
pub const KDF_DEFAULT: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 4,
};

/// HKDF labels (SPEC §5.2). `info` strings are fixed; never derived from input.
/// `AUDIT`, `AUTH` and `BROKER` are used from Phase 2 (audit chain, mutual auth, broker session).
#[allow(dead_code)]
pub mod label {
    pub const KEK_PASSPHRASE: &[u8] = b"kg/v1/kek/passphrase";
    pub const KEK_RECOVERY: &[u8] = b"kg/v1/kek/recovery";
    pub const ENTRY: &[u8] = b"kg/v1/key/entry";
    pub const INDEX: &[u8] = b"kg/v1/key/index";
    pub const HDR: &[u8] = b"kg/v1/key/hdr";
    pub const AUDIT: &[u8] = b"kg/v1/key/audit";
    pub const AUTH: &[u8] = b"kg/v1/key/auth";
    pub const BROKER: &[u8] = b"kg/v1/key/broker";
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u8,
    pub p: u8,
}

impl KdfParams {
    /// Rejects parameters outside the FORMATS caps or below Argon2's own minimums.
    pub fn check(self) -> Result<Self> {
        let min_m = 8u32.saturating_mul(u32::from(self.p));
        if self.m_kib > KDF_M_MAX_KIB || self.m_kib < min_m || self.t == 0 || self.t > KDF_T_MAX {
            return Err(Error::Damaged);
        }
        if self.p == 0 || self.p > KDF_P_MAX {
            return Err(Error::Damaged);
        }
        Ok(self)
    }
}

/// A secret byte string (value, passphrase, recovery key, pepper). Zeroized on drop, never printable.
/// In the broker (once the locked arena exists) the bytes live in `mlock`ed memory (SPEC §5.4); elsewhere on the
/// zero-on-free heap.
pub struct Secret(Store);

enum Store {
    Heap(Box<[u8]>),
    #[cfg(unix)]
    Locked(crate::platform::arena::LockedBuf),
}

/// Set when the arena was full and a secret had to stay on the (unlocked) heap; reported by `status`.
static ARENA_OVERFLOW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn arena_overflowed() -> bool {
    ARENA_OVERFLOW.load(std::sync::atomic::Ordering::Relaxed)
}

impl Secret {
    /// Takes ownership without leaving an unzeroized copy behind: the bytes are copied into the locked arena (if
    /// active) or an exact-size box, and the original buffer (including spare capacity) is wiped.
    pub(crate) fn new(mut v: Vec<u8>) -> Self {
        let s = Self::from_slice(&v);
        v.zeroize();
        s
    }

    pub(crate) fn from_slice(s: &[u8]) -> Self {
        #[cfg(unix)]
        match crate::platform::arena::LockedBuf::copy_from(s) {
            Some(Ok(b)) => return Secret(Store::Locked(b)),
            Some(Err(_)) => ARENA_OVERFLOW.store(true, std::sync::atomic::Ordering::Relaxed),
            None => {}
        }
        Secret(Store::Heap(s.into()))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        match &self.0 {
            Store::Heap(b) => b,
            #[cfg(unix)]
            Store::Locked(b) => b.as_slice(),
        }
    }

    /// Constant-time equality (used for confirmations; length is not secret here).
    pub(crate) fn ct_eq(&self, other: &[u8]) -> bool {
        ct_eq(self.expose(), other)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // locked blocks wipe themselves on drop
        if let Store::Heap(b) = &mut self.0 {
            b.zeroize();
        }
    }
}

macro_rules! key_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(Secret);

        #[allow(dead_code)]
        impl $name {
            pub(crate) fn from_bytes(mut b: [u8; KEY_LEN]) -> Self {
                let k = $name(Secret::from_slice(&b));
                b.zeroize();
                k
            }

            pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
                match self.0.expose().first_chunk::<KEY_LEN>() {
                    Some(k) => k,
                    // unreachable: constructed from exactly KEY_LEN bytes; never fall back to a weak key
                    None => std::process::abort(),
                }
            }
        }
    };
}

key_type!(
    Dek,
    "The vault data-encryption key. Never leaves crypto/vault/broker/cli-auth."
);
key_type!(
    Kek,
    "A key-encryption key derived from a passphrase or recovery key."
);
key_type!(
    Subkey,
    "An HKDF subkey of the DEK (K_entry, K_index, K_hdr, …)."
);

/// `enc(f1) ‖ enc(f2) ‖ …` where `enc(x) = u32 LE len ‖ x` (FORMATS §1). Zeroized on drop, because callers pass
/// secret fields (Argon2 output, pepper) as well.
pub fn enc(fields: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    let mut total: usize = 0;
    for f in fields {
        total = total
            .checked_add(4)
            .and_then(|t| t.checked_add(f.len()))
            .ok_or(Error::Internal(10))?;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    for f in fields {
        let len = u32::try_from(f.len()).map_err(|_| Error::Internal(11))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(f);
    }
    Ok(out)
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::Internal(1))?;
    Ok(b)
}

/// Uniform random index in `0..n` (rejection sampling, no modulo bias).
pub fn random_below(n: u32) -> Result<u32> {
    if n == 0 {
        return Err(Error::Internal(2));
    }
    let zone = u32::MAX.wrapping_sub(u32::MAX.checked_rem(n).ok_or(Error::Internal(2))?);
    loop {
        let v = u32::from_le_bytes(random::<4>()?);
        if v < zone {
            return v.checked_rem(n).ok_or(Error::Internal(2));
        }
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 of at most `limit` bytes read from `r`, in 64 KiB steps (never the whole file in memory; executables can be
/// hundreds of MiB and the broker's budget is 5 MB). `None` if more than `limit` bytes are available.
pub fn sha256_reader(mut r: impl std::io::Read, limit: u64) -> std::io::Result<Option<[u8; 32]>> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(Some(h.finalize().into()));
        }
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if total > limit {
            return Ok(None);
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Argon2id raw output (32 B). Params are checked against the caps first.
pub fn argon2id(passphrase: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Secret> {
    let params = params.check()?;
    let p = argon2::Params::new(
        params.m_kib,
        u32::from(params.t),
        u32::from(params.p),
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Damaged)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
    let mut out = vec![0u8; KEY_LEN];
    if a.hash_password_into(passphrase, salt, &mut out).is_err() {
        out.zeroize();
        return Err(Error::Internal(3));
    }
    Ok(Secret::new(out))
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; KEY_LEN]> {
    let h = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN];
    h.expand(info, &mut okm).map_err(|_| Error::Internal(4))?;
    Ok(okm)
}

/// passphrase KEK = HKDF(salt = uuid, ikm = enc(Argon2id(pass, slot_salt)) ‖ enc(pepper), info = "kg/v1/kek/passphrase")
pub fn kek_passphrase(uuid: &[u8; 16], argon_out: &Secret, pepper: &Secret) -> Result<Kek> {
    let ikm = enc(&[argon_out.expose(), pepper.expose()])?;
    Ok(Kek::from_bytes(hkdf32(uuid, &ikm, label::KEK_PASSPHRASE)?))
}

/// recovery KEK = HKDF(salt = uuid, ikm = recovery_key, info = "kg/v1/kek/recovery")
pub fn kek_recovery(uuid: &[u8; 16], recovery_key: &Secret) -> Result<Kek> {
    Ok(Kek::from_bytes(hkdf32(
        uuid,
        recovery_key.expose(),
        label::KEK_RECOVERY,
    )?))
}

/// subkey = HKDF(salt = uuid, ikm = DEK, info = label)
pub fn subkey(uuid: &[u8; 16], dek: &Dek, info: &'static [u8]) -> Result<Subkey> {
    Ok(Subkey::from_bytes(hkdf32(uuid, dek.expose(), info)?))
}

pub fn new_dek() -> Result<Dek> {
    Ok(Dek::from_bytes(random()?))
}

/// XChaCha20-Poly1305 seal. `key` is any 32-byte key type's bytes.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new(key.into());
    c.encrypt(nonce.into(), Payload { msg: pt, aad })
        .map_err(|_| Error::Internal(5))
}

/// XChaCha20-Poly1305 open. Any failure (wrong key, tamper) is one indistinguishable error, mapped by the caller.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> std::result::Result<Secret, ()> {
    let c = XChaCha20Poly1305::new(key.into());
    c.decrypt(nonce.into(), Payload { msg: ct, aad })
        .map(Secret::new)
        .map_err(|_| ())
}

pub fn wrap_dek(kek: &Kek, nonce: &[u8; NONCE_LEN], aad: &[u8], dek: &Dek) -> Result<Vec<u8>> {
    seal(kek.expose(), nonce, aad, dek.expose())
}

pub fn unwrap_dek(
    kek: &Kek,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> std::result::Result<Dek, ()> {
    let pt = open(kek.expose(), nonce, aad, ct)?;
    let b: [u8; KEY_LEN] = pt.expose().try_into().map_err(|_| ())?;
    Ok(Dek::from_bytes(b))
}

type HmacSha256 = hmac::Hmac<Sha256>;

pub fn hmac(key: &Subkey, data: &[u8]) -> Result<[u8; 32]> {
    let mut m = <HmacSha256 as hmac::KeyInit>::new_from_slice(key.expose())
        .map_err(|_| Error::Internal(6))?;
    m.update(data);
    Ok(m.finalize().into_bytes().into())
}

/// Constant-time MAC verification.
pub fn hmac_verify(key: &Subkey, data: &[u8], tag: &[u8]) -> bool {
    match <HmacSha256 as hmac::KeyInit>::new_from_slice(key.expose()) {
        Ok(mut m) => {
            m.update(data);
            m.verify_slice(tag).is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests;

/// Broker handshake proof (ADR 0004): `HMAC(K_broker, enc("kg/v1/broker") ‖ enc(nc) ‖ enc(nb))`.
pub fn proof_broker(k_broker: &Subkey, nc: &[u8], nb: &[u8]) -> Result<[u8; 32]> {
    hmac(k_broker, &enc(&[b"kg/v1/broker", nc, nb])?)
}

/// Client auth proof (ADR 0004), used by `Approve` (M3): `HMAC(K_auth, enc("kg/v1/client") ‖ enc(nb) ‖ enc(nc) ‖ enc(H(request)))`.
pub fn proof_client(k_auth: &Subkey, nb: &[u8], nc: &[u8], request: &[u8]) -> Result<[u8; 32]> {
    hmac(k_auth, &enc(&[b"kg/v1/client", nb, nc, &sha256(request)])?)
}

pub fn verify_proof(expected: &[u8; 32], got: &[u8]) -> bool {
    ct_eq(expected, got)
}
