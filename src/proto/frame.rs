//! Broker frames (ADR 0004): `u32 length (BE) ‖ u8 version (=1) ‖ u8 type ‖ payload`, max 1 MiB. The length is
//! checked against the cap **before** any allocation; a short read or a bad version closes the connection.
//! Payloads are canonical big-endian TLV (`proto::tlv`). This module never sees plaintext types.

use std::io::{Read, Write};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 1024 * 1024;

/// Message types. Values are stable wire constants; never reuse a number. The registry is complete on purpose;
/// some numbers are reserved before their sender exists.
#[expect(
    dead_code,
    reason = "wire registry (ADR 0004): AUTHED/NOTICE/CHECK* arrive with Phase 3 hooks, CAPTURE/STORED stay reserved"
)]
pub mod ty {
    pub const HELLO: u8 = 1;
    pub const WELCOME: u8 = 2;
    pub const ERR: u8 = 3;
    pub const OK: u8 = 4;
    pub const STATUS: u8 = 10;
    pub const STATUS_REPLY: u8 = 11;
    pub const LIST: u8 = 12;
    pub const LIST_REPLY: u8 = 13;
    pub const SEAL: u8 = 14;
    pub const AUTHED: u8 = 20;
    pub const GRANT_CREATE: u8 = 30;
    pub const GRANT_CREATED: u8 = 31;
    pub const AWAIT_GRANT: u8 = 32;
    pub const GRANT_DECISION: u8 = 33;
    pub const PENDING: u8 = 34;
    pub const PENDING_REPLY: u8 = 35;
    pub const APPROVE: u8 = 36;
    pub const DENY: u8 = 37;
    pub const RUN: u8 = 40;
    pub const STDOUT: u8 = 41;
    pub const STDERR: u8 = 42;
    pub const EXIT: u8 = 43;
    pub const SIGNAL: u8 = 44;
    pub const NOTICE: u8 = 45;
    pub const CAPTURE: u8 = 50;
    pub const STORED: u8 = 51;
    pub const REDACT: u8 = 52;
    pub const REDACTED: u8 = 53;
    pub const CHECK: u8 = 54;
    pub const CHECK_REPLY: u8 = 55;
    pub const AUDIT_VERIFY: u8 = 56;
    pub const AUDIT_OK: u8 = 57;
    pub const UNTRUST: u8 = 58;
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Io,
    Closed,
    TooLarge,
    Version,
}

pub struct Frame {
    pub ty: u8,
    pub payload: Vec<u8>,
}

/// Encode a frame into one buffer (one `write_all`, so frames never interleave).
pub fn encode(ty: u8, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let body = payload.len().checked_add(2).ok_or(FrameError::TooLarge)?;
    if body > MAX_FRAME {
        return Err(FrameError::TooLarge);
    }
    let len = u32::try_from(body).map_err(|_| FrameError::TooLarge)?;
    let mut out = Vec::with_capacity(body.saturating_add(4));
    out.extend_from_slice(&len.to_be_bytes());
    out.push(VERSION);
    out.push(ty);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn write(w: &mut impl Write, ty: u8, payload: &[u8]) -> Result<(), FrameError> {
    let b = encode(ty, payload)?;
    w.write_all(&b)
        .and_then(|()| w.flush())
        .map_err(|_| FrameError::Io)
}

pub fn read(r: &mut impl Read) -> Result<Frame, FrameError> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(_) => return Err(FrameError::Io),
    }
    let len = usize::try_from(u32::from_be_bytes(hdr)).map_err(|_| FrameError::TooLarge)?;
    if !(2..=MAX_FRAME).contains(&len) {
        return Err(FrameError::TooLarge);
    }
    let mut vt = [0u8; 2];
    r.read_exact(&mut vt).map_err(|_| FrameError::Io)?;
    let [ver, ty] = vt;
    if ver != VERSION {
        return Err(FrameError::Version);
    }
    let mut payload = vec![0u8; len.saturating_sub(2)];
    r.read_exact(&mut payload).map_err(|_| FrameError::Io)?;
    Ok(Frame { ty, payload })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    #[test]
    fn roundtrip_and_limits() {
        let b = encode(ty::STATUS, b"abc").unwrap();
        assert_eq!(b, [0, 0, 0, 5, 1, 10, b'a', b'b', b'c']);
        let f = read(&mut &b[..]).unwrap();
        assert_eq!((f.ty, f.payload.as_slice()), (ty::STATUS, &b"abc"[..]));
        // oversized length is rejected before allocating
        let huge = [0x7f, 0xff, 0xff, 0xff, 1, 1];
        assert_eq!(read(&mut &huge[..]).err(), Some(FrameError::TooLarge));
        assert_eq!(
            read(&mut &[0u8, 0, 0, 1, 1][..]).err(),
            Some(FrameError::TooLarge)
        );
        assert_eq!(
            read(&mut &[0u8, 0, 0, 2, 9, 1][..]).err(),
            Some(FrameError::Version)
        );
        assert_eq!(read(&mut &[][..]).err(), Some(FrameError::Closed));
        for i in 1..b.len() {
            assert!(read(&mut &b[..i]).is_err());
        }
        assert!(encode(1, &vec![0u8; MAX_FRAME]).is_err());
    }
}
