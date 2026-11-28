//! `vault.kgt` binary layout, format version 1 (FORMATS §1). Little-endian.
//!
//! The parser is total and refuses `format_version` > supported and any field outside its cap **before** running the
//! KDF or allocating: `slot_count` 1..=8, KDF caps, `index_len` ≤ 16 MiB, `entry_count` ≤ 1 000, `ct_len` ≤
//! 64 KiB + 16, `handle_len` ≤ 255, and every length ≤ the remaining input. This module only handles ciphertext.

use crate::crypto::{self, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};

pub const MAGIC: &[u8; 4] = b"KGNT";
pub const FORMAT_VERSION: u16 = 1;
pub const MAX_SLOTS: u8 = 8;
pub const MAX_INDEX_LEN: u32 = 16 * 1024 * 1024;
pub const MAX_ENTRIES: u32 = 1_000;
pub const MAX_CT_LEN: u32 = 64 * 1024 + 16;
pub const SLOT_LEN: usize = 112;
pub const WRAPPED_LEN: usize = 48;
/// Upper bound for the whole file, checked against the file size before reading it.
pub const MAX_FILE_LEN: u64 = 31
    + 8 * 112
    + 32
    + 4
    + 24
    + 16 * 1024 * 1024
    + 4
    + 1000 * (1 + 255 + 4 + 24 + 4 + 64 * 1024 + 16);

/// Slot kinds (FORMATS §1). `Prf` and `OsUv` arrive in Phase 6; unknown kinds are preserved, never used.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotKind {
    Passphrase = 1,
    Recovery = 2,
    Prf = 3,
    OsUv = 4,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Slot {
    /// Raw kind byte; unknown kinds are preserved but never used.
    pub kind: u8,
    pub slot_id: [u8; 16],
    pub kdf_id: u8,
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub wrapped: [u8; WRAPPED_LEN],
}

impl Slot {
    /// Slot AAD (FORMATS §1): SHA-256 over the length-prefixed slot fields, without `generation`, nonce or ciphertext.
    pub fn aad(&self, uuid: &[u8; 16]) -> Result<[u8; 32]> {
        let e = crypto::enc(&[
            MAGIC,
            &FORMAT_VERSION.to_le_bytes(),
            uuid,
            &[self.kind],
            &self.slot_id,
            &[self.kdf_id],
            &self.kdf.m_kib.to_le_bytes(),
            &[self.kdf.t],
            &[self.kdf.p],
            &self.salt,
        ])?;
        Ok(crypto::sha256(&e))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RawEntry {
    pub handle: String,
    pub version: u32,
    pub nonce: [u8; NONCE_LEN],
    pub ct: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VaultFile {
    pub uuid: [u8; 16],
    pub generation: u64,
    pub slots: Vec<Slot>,
    pub header_mac: [u8; 32],
    pub index_nonce: [u8; NONCE_LEN],
    pub index_ct: Vec<u8>,
    pub entries: Vec<RawEntry>,
}

/// Bounds-checked cursor; every read fails instead of panicking.
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Damaged)?;
        let s = self.b.get(self.pos..end).ok_or(Error::Damaged)?;
        self.pos = end;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Damaged)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }
}

fn check_len(len: u32, cap: u32, cur: &Cur<'_>) -> Result<usize> {
    let n = usize::try_from(len).map_err(|_| Error::Damaged)?;
    if len > cap || n > cur.remaining() {
        return Err(Error::Damaged);
    }
    Ok(n)
}

/// Header bytes covered by `header_mac`: magic … last slot.
pub fn header_bytes(uuid: &[u8; 16], generation: u64, slots: &[Slot]) -> Result<Vec<u8>> {
    let count = u8::try_from(slots.len()).map_err(|_| Error::Internal(20))?;
    if count == 0 || count > MAX_SLOTS {
        return Err(Error::Internal(21));
    }
    let mut h = Vec::with_capacity(31usize.saturating_add(slots.len().saturating_mul(SLOT_LEN)));
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    h.extend_from_slice(uuid);
    h.extend_from_slice(&generation.to_le_bytes());
    h.push(count);
    for s in slots {
        h.push(s.kind);
        h.extend_from_slice(&s.slot_id);
        h.push(s.kdf_id);
        h.extend_from_slice(&s.kdf.m_kib.to_le_bytes());
        h.push(s.kdf.t);
        h.push(s.kdf.p);
        h.extend_from_slice(&s.salt);
        h.extend_from_slice(&s.nonce);
        h.extend_from_slice(&s.wrapped);
    }
    Ok(h)
}

/// Peek the format version without parsing anything else (for migrations and "upgrade keygent").
pub fn peek_version(b: &[u8]) -> Result<u16> {
    let mut c = Cur { b, pos: 0 };
    if c.take(4)? != MAGIC {
        return Err(Error::Damaged);
    }
    c.u16()
}

pub fn parse(b: &[u8]) -> Result<(VaultFile, usize)> {
    if u64::try_from(b.len()).map_err(|_| Error::Damaged)? > MAX_FILE_LEN {
        return Err(Error::Damaged);
    }
    let mut c = Cur { b, pos: 0 };
    if c.take(4)? != MAGIC {
        return Err(Error::Damaged);
    }
    let ver = c.u16()?;
    if ver > FORMAT_VERSION {
        return Err(Error::FormatTooNew(ver));
    }
    if ver != FORMAT_VERSION {
        return Err(Error::Damaged);
    }
    let uuid = c.arr::<16>()?;
    let generation = c.u64()?;
    let count = c.u8()?;
    if count == 0 || count > MAX_SLOTS {
        return Err(Error::Damaged);
    }
    let mut slots = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let kind = c.u8()?;
        let slot_id = c.arr()?;
        let kdf_id = c.u8()?;
        let m_kib = c.u32()?;
        let t = c.u8()?;
        let p = c.u8()?;
        let kdf = KdfParams { m_kib, t, p };
        // caps are checked here, before any KDF can run (kdf_id 0 = none, used by the recovery slot)
        match kdf_id {
            0 if m_kib == 0 && t == 0 && p == 0 => {}
            1 => {
                kdf.check()?;
            }
            _ => return Err(Error::Damaged),
        }
        slots.push(Slot {
            kind,
            slot_id,
            kdf_id,
            kdf,
            salt: c.arr()?,
            nonce: c.arr()?,
            wrapped: c.arr()?,
        });
    }
    let header_len = c.pos;
    let header_mac = c.arr()?;
    let index_len = c.u32()?;
    let index_nonce = c.arr()?;
    let n = check_len(index_len, MAX_INDEX_LEN, &c)?;
    if n < TAG_LEN {
        return Err(Error::Damaged);
    }
    let index_ct = c.take(n)?.to_vec();
    let entry_count = c.u32()?;
    if entry_count > MAX_ENTRIES {
        return Err(Error::Damaged);
    }
    let mut entries = Vec::with_capacity(usize::try_from(entry_count).map_err(|_| Error::Damaged)?);
    for _ in 0..entry_count {
        let hl = usize::from(c.u8()?);
        let handle = std::str::from_utf8(c.take(hl)?)
            .map_err(|_| Error::Damaged)?
            .to_owned();
        let version = c.u32()?;
        let nonce = c.arr()?;
        let ct_len = c.u32()?;
        let n = check_len(ct_len, MAX_CT_LEN, &c)?;
        if n < TAG_LEN {
            return Err(Error::Damaged);
        }
        entries.push(RawEntry {
            handle,
            version,
            nonce,
            ct: c.take(n)?.to_vec(),
        });
    }
    if c.remaining() != 0 {
        return Err(Error::Damaged);
    }
    Ok((
        VaultFile {
            uuid,
            generation,
            slots,
            header_mac,
            index_nonce,
            index_ct,
            entries,
        },
        header_len,
    ))
}

pub fn serialize(v: &VaultFile) -> Result<Vec<u8>> {
    let mut out = header_bytes(&v.uuid, v.generation, &v.slots)?;
    out.extend_from_slice(&v.header_mac);
    let il = u32::try_from(v.index_ct.len()).map_err(|_| Error::TooLarge("16 MiB index"))?;
    if il > MAX_INDEX_LEN {
        return Err(Error::TooLarge("16 MiB index"));
    }
    out.extend_from_slice(&il.to_le_bytes());
    out.extend_from_slice(&v.index_nonce);
    out.extend_from_slice(&v.index_ct);
    let ec = u32::try_from(v.entries.len()).map_err(|_| Error::TooLarge("1000 secrets"))?;
    if ec > MAX_ENTRIES {
        return Err(Error::TooLarge("1000 secrets"));
    }
    out.extend_from_slice(&ec.to_le_bytes());
    for e in &v.entries {
        let hl = u8::try_from(e.handle.len()).map_err(|_| Error::InvalidHandle)?;
        out.push(hl);
        out.extend_from_slice(e.handle.as_bytes());
        out.extend_from_slice(&e.version.to_le_bytes());
        out.extend_from_slice(&e.nonce);
        let cl = u32::try_from(e.ct.len()).map_err(|_| Error::ValueSize)?;
        if cl > MAX_CT_LEN {
            return Err(Error::ValueSize);
        }
        out.extend_from_slice(&cl.to_le_bytes());
        out.extend_from_slice(&e.ct);
    }
    Ok(out)
}

/// Index AAD = enc(uuid) ‖ enc("index") ‖ enc(u64 generation).
pub fn index_aad(uuid: &[u8; 16], generation: u64) -> Result<Vec<u8>> {
    Ok(crypto::enc(&[uuid, b"index", &generation.to_le_bytes()])?.to_vec())
}

/// Entry AAD = enc(uuid) ‖ enc(handle) ‖ enc(u32 version).
pub fn entry_aad(uuid: &[u8; 16], handle: &str, version: u32) -> Result<Vec<u8>> {
    Ok(crypto::enc(&[uuid, handle.as_bytes(), &version.to_le_bytes()])?.to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn sample() -> VaultFile {
        VaultFile {
            uuid: [1; 16],
            generation: 42,
            slots: vec![
                Slot {
                    kind: 1,
                    slot_id: [2; 16],
                    kdf_id: 1,
                    kdf: crypto::KDF_DEFAULT,
                    salt: [3; 16],
                    nonce: [4; 24],
                    wrapped: [5; 48],
                },
                Slot {
                    kind: 2,
                    slot_id: [6; 16],
                    kdf_id: 0,
                    kdf: KdfParams {
                        m_kib: 0,
                        t: 0,
                        p: 0,
                    },
                    salt: [0; 16],
                    nonce: [7; 24],
                    wrapped: [8; 48],
                },
            ],
            header_mac: [9; 32],
            index_nonce: [10; 24],
            index_ct: vec![11; 40],
            entries: vec![RawEntry {
                handle: "stripe/live".into(),
                version: 3,
                nonce: [12; 24],
                ct: vec![13; 30],
            }],
        }
    }

    #[test]
    fn roundtrip_and_layout() {
        let v = sample();
        let b = serialize(&v).unwrap();
        let (p, hl) = parse(&b).unwrap();
        assert_eq!(p, v);
        assert_eq!(hl, 31 + 2 * SLOT_LEN);
        assert_eq!(&b[..4], b"KGNT");
        assert_eq!(&b[4..6], &[1, 0]);
        assert_eq!(b[30], 2);
    }

    #[test]
    fn every_truncation_fails_without_panic() {
        let b = serialize(&sample()).unwrap();
        for i in 0..b.len() {
            assert!(parse(&b[..i]).is_err(), "{i}");
        }
        let mut x = b.clone();
        x.push(0);
        assert!(parse(&x).is_err(), "trailing byte");
    }

    #[test]
    fn caps_rejected_before_kdf() {
        let mut v = sample();
        v.slots[0].kdf.m_kib = crypto::KDF_M_MAX_KIB + 1;
        assert_eq!(parse(&serialize(&v).unwrap()).unwrap_err(), Error::Damaged);
        let mut v = sample();
        v.slots[0].kdf.t = 200;
        assert!(parse(&serialize(&v).unwrap()).is_err());
        let mut b = serialize(&sample()).unwrap();
        b[30] = 9; // slot_count
        assert!(parse(&b).is_err());
        b[30] = 0;
        assert!(parse(&b).is_err());
    }

    #[test]
    fn oversized_lengths_rejected() {
        let b = serialize(&sample()).unwrap();
        let hl = 31 + 2 * SLOT_LEN;
        // index_len just after header + mac
        let mut x = b.clone();
        x[hl + 32..hl + 36].copy_from_slice(&(MAX_INDEX_LEN + 1).to_le_bytes());
        assert!(parse(&x).is_err());
        let mut y = b.clone();
        y[hl + 32..hl + 36].copy_from_slice(&1000u32.to_le_bytes()); // > remaining
        assert!(parse(&y).is_err());
    }

    #[test]
    fn newer_format_refused() {
        let mut b = serialize(&sample()).unwrap();
        b[4] = 2;
        assert_eq!(parse(&b).unwrap_err(), Error::FormatTooNew(2));
        assert_eq!(peek_version(&b).unwrap(), 2);
    }

    #[test]
    fn slot_aad_excludes_generation_and_is_field_bound() {
        let v = sample();
        let a = v.slots[0].aad(&v.uuid).unwrap();
        let mut s = v.slots[0].clone();
        s.nonce = [0; 24];
        s.wrapped = [0; 48];
        assert_eq!(s.aad(&v.uuid).unwrap(), a);
        s.kdf.t = 4;
        assert_ne!(s.aad(&v.uuid).unwrap(), a);
        assert_ne!(v.slots[0].aad(&[2; 16]).unwrap(), a);
    }
}
