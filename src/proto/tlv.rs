//! Canonical TLV codec (FORMATS §2). Record = `u16 tag ‖ u32 len ‖ value`; little-endian for the vault index,
//! big-endian for the broker protocol (ADR 0004).
//!
//! The decoder is total: every length is checked against the remaining input before use, depth ≤ 4, total ≤ 16 MiB,
//! tags must appear in ascending order, a non-list tag at most once, and leftover (unknown) tags are an error.
//! The encoder never leaves stale copies of its buffer behind when it grows (old buffers are zeroized), because the
//! vault index plaintext it builds can hold secret bytes. This module itself never names a secret type.

use zeroize::{Zeroize, Zeroizing};

pub const MAX_TOTAL: usize = 16 * 1024 * 1024;
pub const MAX_DEPTH: u8 = 4;
const HDR: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    /// Broker protocol (Phase 2, ADR 0004).
    #[allow(dead_code)]
    Big,
}

/// One record: tag, value, bytes consumed.
type Record<'a> = (u16, &'a [u8], usize);

#[derive(Debug, PartialEq, Eq)]
pub enum TlvError {
    Truncated,
    TooLarge,
    TooDeep,
    /// Missing required tag, duplicate, out-of-order or unknown tag.
    Shape(u16),
    /// Value has the wrong width, bad bool byte or invalid UTF-8.
    Value(u16),
}

// ---------------------------------------------------------------- encoder

pub struct Encoder {
    buf: Zeroizing<Vec<u8>>,
    endian: Endian,
    depth: u8,
}

impl Encoder {
    pub fn new(endian: Endian) -> Self {
        Encoder {
            buf: Zeroizing::new(Vec::with_capacity(4096)),
            endian,
            depth: 0,
        }
    }

    /// Grow without leaving the old allocation readable.
    fn reserve(&mut self, extra: usize) {
        let need = self.buf.len().saturating_add(extra);
        if need <= self.buf.capacity() {
            return;
        }
        let mut n = Vec::with_capacity(need.max(self.buf.capacity().saturating_mul(2)));
        n.extend_from_slice(&self.buf);
        let mut old = std::mem::replace(&mut *self.buf, n);
        old.zeroize();
    }

    fn put(&mut self, b: &[u8]) {
        self.reserve(b.len());
        self.buf.extend_from_slice(b);
    }

    fn header(&mut self, tag: u16, len: u32) {
        let (t, l) = match self.endian {
            Endian::Little => (tag.to_le_bytes(), len.to_le_bytes()),
            Endian::Big => (tag.to_be_bytes(), len.to_be_bytes()),
        };
        self.put(&t);
        self.put(&l);
    }

    pub fn bytes(&mut self, tag: u16, v: &[u8]) -> Result<(), TlvError> {
        let len = u32::try_from(v.len()).map_err(|_| TlvError::TooLarge)?;
        if self.buf.len().saturating_add(HDR).saturating_add(v.len()) > MAX_TOTAL {
            return Err(TlvError::TooLarge);
        }
        self.header(tag, len);
        self.put(v);
        Ok(())
    }

    pub fn utf8(&mut self, tag: u16, v: &str) -> Result<(), TlvError> {
        self.bytes(tag, v.as_bytes())
    }

    pub fn u8(&mut self, tag: u16, v: u8) -> Result<(), TlvError> {
        self.bytes(tag, &[v])
    }

    pub fn bool(&mut self, tag: u16, v: bool) -> Result<(), TlvError> {
        self.u8(tag, u8::from(v))
    }

    pub fn u16(&mut self, tag: u16, v: u16) -> Result<(), TlvError> {
        let b = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.bytes(tag, &b)
    }

    pub fn u32(&mut self, tag: u16, v: u32) -> Result<(), TlvError> {
        let b = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.bytes(tag, &b)
    }

    pub fn u64(&mut self, tag: u16, v: u64) -> Result<(), TlvError> {
        let b = match self.endian {
            Endian::Little => v.to_le_bytes(),
            Endian::Big => v.to_be_bytes(),
        };
        self.bytes(tag, &b)
    }

    /// Nested struct: the closure writes the inner records; the length is back-patched.
    pub fn nested(
        &mut self,
        tag: u16,
        f: impl FnOnce(&mut Encoder) -> Result<(), TlvError>,
    ) -> Result<(), TlvError> {
        if self.depth >= MAX_DEPTH {
            return Err(TlvError::TooDeep);
        }
        self.header(tag, 0);
        let start = self.buf.len();
        self.depth = self.depth.saturating_add(1);
        f(self)?;
        self.depth = self.depth.saturating_sub(1);
        let len =
            u32::try_from(self.buf.len().saturating_sub(start)).map_err(|_| TlvError::TooLarge)?;
        if self.buf.len() > MAX_TOTAL {
            return Err(TlvError::TooLarge);
        }
        let lb = match self.endian {
            Endian::Little => len.to_le_bytes(),
            Endian::Big => len.to_be_bytes(),
        };
        let at = start.checked_sub(4).ok_or(TlvError::Truncated)?;
        self.buf
            .get_mut(at..start)
            .ok_or(TlvError::Truncated)?
            .copy_from_slice(&lb);
        Ok(())
    }

    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

// ---------------------------------------------------------------- decoder

/// Pull decoder over one TLV sequence. Fields must be requested in ascending tag order; `finish()` fails if any
/// record is left over (unknown tag) — that is what makes the format canonical.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    endian: Endian,
    depth: u8,
    last_tag: Option<u16>,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8], endian: Endian) -> Result<Self, TlvError> {
        if buf.len() > MAX_TOTAL {
            return Err(TlvError::TooLarge);
        }
        Ok(Decoder {
            buf,
            pos: 0,
            endian,
            depth: 0,
            last_tag: None,
        })
    }

    fn peek(&self) -> Result<Option<Record<'a>>, TlvError> {
        let rest = self.buf.get(self.pos..).ok_or(TlvError::Truncated)?;
        if rest.is_empty() {
            return Ok(None);
        }
        let h = rest.get(..HDR).ok_or(TlvError::Truncated)?;
        let (t, l) = (
            h.get(..2).ok_or(TlvError::Truncated)?,
            h.get(2..HDR).ok_or(TlvError::Truncated)?,
        );
        let t: [u8; 2] = t.try_into().map_err(|_| TlvError::Truncated)?;
        let l: [u8; 4] = l.try_into().map_err(|_| TlvError::Truncated)?;
        let (tag, len) = match self.endian {
            Endian::Little => (u16::from_le_bytes(t), u32::from_le_bytes(l)),
            Endian::Big => (u16::from_be_bytes(t), u32::from_be_bytes(l)),
        };
        let len = usize::try_from(len).map_err(|_| TlvError::TooLarge)?;
        let end = HDR.checked_add(len).ok_or(TlvError::TooLarge)?;
        let v = rest.get(HDR..end).ok_or(TlvError::Truncated)?;
        Ok(Some((tag, v, end)))
    }

    fn order(&mut self, tag: u16, list: bool) -> Result<(), TlvError> {
        if let Some(last) = self.last_tag
            && (tag < last || (tag == last && !list))
        {
            return Err(TlvError::Shape(tag));
        }
        self.last_tag = Some(tag);
        Ok(())
    }

    /// Optional raw value for `tag`.
    pub fn opt(&mut self, tag: u16) -> Result<Option<&'a [u8]>, TlvError> {
        self.order(tag, false)?;
        match self.peek()? {
            Some((t, v, n)) if t == tag => {
                self.pos = self.pos.saturating_add(n);
                // a second record with the same non-list tag is a duplicate
                if matches!(self.peek()?, Some((t2, _, _)) if t2 == tag) {
                    return Err(TlvError::Shape(tag));
                }
                Ok(Some(v))
            }
            Some((t, _, _)) if t < tag => Err(TlvError::Shape(t)),
            _ => Ok(None),
        }
    }

    pub fn req(&mut self, tag: u16) -> Result<&'a [u8], TlvError> {
        self.opt(tag)?.ok_or(TlvError::Shape(tag))
    }

    /// All consecutive records with `tag` (possibly none).
    pub fn list(&mut self, tag: u16) -> Result<Vec<&'a [u8]>, TlvError> {
        self.order(tag, true)?;
        let mut out = Vec::new();
        loop {
            match self.peek()? {
                Some((t, v, n)) if t == tag => {
                    self.pos = self.pos.saturating_add(n);
                    out.push(v);
                }
                Some((t, _, _)) if t < tag => return Err(TlvError::Shape(t)),
                _ => return Ok(out),
            }
        }
    }

    /// Decoder for a nested struct value.
    pub fn sub(&self, v: &'a [u8]) -> Result<Decoder<'a>, TlvError> {
        if self.depth >= MAX_DEPTH {
            return Err(TlvError::TooDeep);
        }
        Ok(Decoder {
            buf: v,
            pos: 0,
            endian: self.endian,
            depth: self.depth.saturating_add(1),
            last_tag: None,
        })
    }

    pub fn finish(self) -> Result<(), TlvError> {
        match self.peek()? {
            None => Ok(()),
            Some((t, _, _)) => Err(TlvError::Shape(t)),
        }
    }

    // typed helpers

    pub fn as_u8(&self, tag: u16, v: &[u8]) -> Result<u8, TlvError> {
        let a: [u8; 1] = v.try_into().map_err(|_| TlvError::Value(tag))?;
        Ok(a[0])
    }

    pub fn as_bool(&self, tag: u16, v: &[u8]) -> Result<bool, TlvError> {
        match self.as_u8(tag, v)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(TlvError::Value(tag)),
        }
    }

    pub fn as_u16(&self, tag: u16, v: &[u8]) -> Result<u16, TlvError> {
        let a: [u8; 2] = v.try_into().map_err(|_| TlvError::Value(tag))?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(a),
            Endian::Big => u16::from_be_bytes(a),
        })
    }

    pub fn as_u32(&self, tag: u16, v: &[u8]) -> Result<u32, TlvError> {
        let a: [u8; 4] = v.try_into().map_err(|_| TlvError::Value(tag))?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(a),
            Endian::Big => u32::from_be_bytes(a),
        })
    }

    pub fn as_u64(&self, tag: u16, v: &[u8]) -> Result<u64, TlvError> {
        let a: [u8; 8] = v.try_into().map_err(|_| TlvError::Value(tag))?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(a),
            Endian::Big => u64::from_be_bytes(a),
        })
    }

    pub fn as_str(&self, tag: u16, v: &'a [u8]) -> Result<&'a str, TlvError> {
        std::str::from_utf8(v).map_err(|_| TlvError::Value(tag))
    }

    pub fn as_array<const N: usize>(&self, tag: u16, v: &[u8]) -> Result<[u8; N], TlvError> {
        v.try_into().map_err(|_| TlvError::Value(tag))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    #![allow(clippy::cast_possible_truncation, clippy::type_complexity)]
    use super::*;

    fn sample(e: Endian) -> Vec<u8> {
        let mut enc = Encoder::new(e);
        enc.u16(1, 7).unwrap();
        enc.nested(2, |s| {
            s.utf8(1, "a")?;
            s.bool(2, true)
        })
        .unwrap();
        enc.nested(2, |s| {
            s.utf8(1, "b")?;
            s.bool(2, false)
        })
        .unwrap();
        enc.u64(3, 9).unwrap();
        enc.finish().to_vec()
    }

    fn read(b: &[u8], e: Endian) -> Result<(u16, Vec<(String, bool)>, u64), TlvError> {
        let mut d = Decoder::new(b, e)?;
        let v = d.req(1)?;
        let ver = d.as_u16(1, v)?;
        let mut items = Vec::new();
        for raw in d.list(2)? {
            let mut s = d.sub(raw)?;
            let a = s.req(1)?;
            let name = s.as_str(1, a)?.to_owned();
            let f = s.req(2)?;
            let flag = s.as_bool(2, f)?;
            s.finish()?;
            items.push((name, flag));
        }
        let n = d.req(3)?;
        let n = d.as_u64(3, n)?;
        d.finish()?;
        Ok((ver, items, n))
    }

    #[test]
    fn roundtrip_both_endians() {
        for e in [Endian::Little, Endian::Big] {
            let (v, items, n) = read(&sample(e), e).unwrap();
            assert_eq!((v, n), (7, 9));
            assert_eq!(items, vec![("a".into(), true), ("b".into(), false)]);
        }
    }

    #[test]
    fn golden_le_bytes() {
        let hex: String = sample(Endian::Little)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        let g = include_str!("../../tests/golden/tlv/sample_le.hex").trim();
        assert_eq!(hex, g);
    }

    #[test]
    fn rejects_unknown_duplicate_order_and_truncation() {
        let good = sample(Endian::Little);
        // unknown trailing tag
        let mut b = good.clone();
        b.extend_from_slice(&[9, 0, 0, 0, 0, 0]);
        assert_eq!(read(&b, Endian::Little).unwrap_err(), TlvError::Shape(9));
        // duplicate non-list tag 1
        let mut d = vec![1, 0, 2, 0, 0, 0, 7, 0];
        d.extend_from_slice(&good);
        assert!(read(&d, Endian::Little).is_err());
        // truncation at every length never panics and always errors
        for i in 0..good.len() {
            assert!(read(&good[..i], Endian::Little).is_err(), "len {i}");
        }
        // bad bool byte
        let mut bb = good.clone();
        let pos = bb.iter().position(|&x| x == b'a').unwrap() + 7; // value of tag 2 inside first struct
        bb[pos] = 2;
        assert!(read(&bb, Endian::Little).is_err());
        // oversized length field
        let huge = [1u8, 0, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            read(&huge, Endian::Little).unwrap_err(),
            TlvError::Truncated
        );
    }

    #[test]
    fn depth_is_capped() {
        let mut e = Encoder::new(Endian::Little);
        let r = e.nested(1, |a| {
            a.nested(1, |b| {
                b.nested(1, |c| c.nested(1, |d| d.nested(1, |_| Ok(()))))
            })
        });
        assert_eq!(r.unwrap_err(), TlvError::TooDeep);
    }

    #[test]
    fn random_input_never_panics() {
        // cheap deterministic fuzz; the cargo-fuzz target covers this properly
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 64) as usize;
            let bytes: Vec<u8> = (0..len).map(|i| (x >> (i % 8 * 8)) as u8).collect();
            let _ = read(&bytes, Endian::Little);
            let _ = read(&bytes, Endian::Big);
        }
    }
}
