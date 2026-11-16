//! Broker request/response payloads (ADR 0004), canonical big-endian TLV. Decoders are total and reject unknown,
//! duplicate or out-of-order tags. No message here carries a secret value (ADR 0012: no plaintext responses).

use super::tags::proto as t;
use super::tlv::{Decoder, Encoder, Endian, TlvError};

pub const NONCE_LEN: usize = 32;
pub const MAX_STR: usize = 4096;

/// Connection classes (ADR 0004) for the reserved-connection pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Hook = 1,
    Run = 2,
    Auth = 3,
    Control = 4,
    Ui = 5,
}

impl Class {
    pub fn from_u8(b: u8) -> Option<Class> {
        Some(match b {
            1 => Class::Hook,
            2 => Class::Run,
            3 => Class::Auth,
            4 => Class::Control,
            5 => Class::Ui,
            _ => return None,
        })
    }
}

/// Protocol error codes (ADR 0004 "Errors"); the message text is the canonical ERRORS.md line.
#[allow(dead_code)]
pub mod code {
    pub const APPROVAL_DENIED: u16 = 1;
    pub const NOT_TRUSTED: u16 = 2;
    pub const POLICY_DENIED: u16 = 3;
    pub const SEALED: u16 = 4;
    pub const VERSION_MISMATCH: u16 = 5;
    pub const INTERNAL: u16 = 6;
    pub const RATE_LIMITED: u16 = 7;
    pub const TOO_LARGE: u16 = 8;
    pub const NEEDS_AUTH: u16 = 9;
    pub const BAD_REQUEST: u16 = 10;
}

fn enc() -> Encoder {
    Encoder::new(Endian::Big)
}

fn done(e: Encoder) -> Vec<u8> {
    e.finish().to_vec()
}

fn string(d: &Decoder<'_>, tag: u16, v: &[u8]) -> Result<String, TlvError> {
    if v.len() > MAX_STR {
        return Err(TlvError::TooLarge);
    }
    Ok(d.as_str(tag, v)?.to_owned())
}

// ---------------------------------------------------------------- handshake

pub struct Hello {
    pub build_id: String,
    pub nonce: [u8; NONCE_LEN],
    pub class: Class,
}

impl Hello {
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.utf8(t::BUILD_ID, &self.build_id)?;
        e.bytes(t::NONCE, &self.nonce)?;
        e.u8(t::CLASS, self.class as u8)?;
        Ok(done(e))
    }
    pub fn decode(b: &[u8]) -> Result<Hello, TlvError> {
        let mut d = Decoder::new(b, Endian::Big)?;
        let v = d.req(t::BUILD_ID)?;
        let build_id = string(&d, t::BUILD_ID, v)?;
        let v = d.req(t::NONCE)?;
        let nonce = d.as_array(t::NONCE, v)?;
        let v = d.req(t::CLASS)?;
        let class = Class::from_u8(d.as_u8(t::CLASS, v)?).ok_or(TlvError::Value(t::CLASS))?;
        d.finish()?;
        Ok(Hello {
            build_id,
            nonce,
            class,
        })
    }
}

pub struct Welcome {
    pub build_id: String,
    pub nonce: [u8; NONCE_LEN],
    pub proof: [u8; 32],
}

impl Welcome {
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.utf8(t::BUILD_ID, &self.build_id)?;
        e.bytes(t::NONCE, &self.nonce)?;
        e.bytes(t::PROOF, &self.proof)?;
        Ok(done(e))
    }
    pub fn decode(b: &[u8]) -> Result<Welcome, TlvError> {
        let mut d = Decoder::new(b, Endian::Big)?;
        let v = d.req(t::BUILD_ID)?;
        let build_id = string(&d, t::BUILD_ID, v)?;
        let v = d.req(t::NONCE)?;
        let nonce = d.as_array(t::NONCE, v)?;
        let v = d.req(t::PROOF)?;
        let proof = d.as_array(t::PROOF, v)?;
        d.finish()?;
        Ok(Welcome {
            build_id,
            nonce,
            proof,
        })
    }
}

// ---------------------------------------------------------------- errors

pub struct ErrMsg {
    pub code: u16,
    pub message: String,
}

impl ErrMsg {
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.u16(t::CODE, self.code)?;
        e.utf8(t::MESSAGE, &self.message)?;
        Ok(done(e))
    }
    pub fn decode(b: &[u8]) -> Result<ErrMsg, TlvError> {
        let mut d = Decoder::new(b, Endian::Big)?;
        let v = d.req(t::CODE)?;
        let code = d.as_u16(t::CODE, v)?;
        let v = d.req(t::MESSAGE)?;
        let message = string(&d, t::MESSAGE, v)?;
        d.finish()?;
        Ok(ErrMsg { code, message })
    }
}

// ---------------------------------------------------------------- status / list

#[derive(Debug, PartialEq, Eq)]
pub struct StatusReply {
    pub pid: u32,
    pub ttl_left_secs: u64,
    pub idle_left_secs: u64,
    pub handles: u32,
    pub no_dumps: bool,
    pub mlockall: bool,
}

impl StatusReply {
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.u32(t::PID, self.pid)?;
        e.u64(t::TTL_LEFT, self.ttl_left_secs)?;
        e.u64(t::IDLE_LEFT, self.idle_left_secs)?;
        e.u32(t::HANDLE_COUNT, self.handles)?;
        e.bool(t::NO_DUMPS, self.no_dumps)?;
        e.bool(t::MLOCKALL, self.mlockall)?;
        Ok(done(e))
    }
    pub fn decode(b: &[u8]) -> Result<StatusReply, TlvError> {
        let mut d = Decoder::new(b, Endian::Big)?;
        let v = d.req(t::PID)?;
        let pid = d.as_u32(t::PID, v)?;
        let v = d.req(t::TTL_LEFT)?;
        let ttl_left_secs = d.as_u64(t::TTL_LEFT, v)?;
        let v = d.req(t::IDLE_LEFT)?;
        let idle_left_secs = d.as_u64(t::IDLE_LEFT, v)?;
        let v = d.req(t::HANDLE_COUNT)?;
        let handles = d.as_u32(t::HANDLE_COUNT, v)?;
        let v = d.req(t::NO_DUMPS)?;
        let no_dumps = d.as_bool(t::NO_DUMPS, v)?;
        let v = d.req(t::MLOCKALL)?;
        let mlockall = d.as_bool(t::MLOCKALL, v)?;
        d.finish()?;
        Ok(StatusReply {
            pid,
            ttl_left_secs,
            idle_left_secs,
            handles,
            no_dumps,
            mlockall,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListEntry {
    pub handle: String,
    pub env_name: String,
    pub mode: u8,
    pub binding: u8,
    pub exposed: bool,
    pub description: String,
}

pub fn encode_list(entries: &[ListEntry]) -> Result<Vec<u8>, TlvError> {
    let mut e = enc();
    for x in entries {
        e.nested(t::ENTRY, |e| {
            e.utf8(t::E_HANDLE, &x.handle)?;
            e.utf8(t::E_ENV, &x.env_name)?;
            e.u8(t::E_MODE, x.mode)?;
            e.u8(t::E_BINDING, x.binding)?;
            e.bool(t::E_EXPOSED, x.exposed)?;
            e.utf8(t::E_DESCRIPTION, &x.description)
        })?;
    }
    Ok(done(e))
}

pub fn decode_list(b: &[u8]) -> Result<Vec<ListEntry>, TlvError> {
    let mut d = Decoder::new(b, Endian::Big)?;
    let mut out = Vec::new();
    for raw in d.list(t::ENTRY)? {
        let mut s = d.sub(raw)?;
        let v = s.req(t::E_HANDLE)?;
        let handle = string(&s, t::E_HANDLE, v)?;
        let v = s.req(t::E_ENV)?;
        let env_name = string(&s, t::E_ENV, v)?;
        let v = s.req(t::E_MODE)?;
        let mode = s.as_u8(t::E_MODE, v)?;
        let v = s.req(t::E_BINDING)?;
        let binding = s.as_u8(t::E_BINDING, v)?;
        let v = s.req(t::E_EXPOSED)?;
        let exposed = s.as_bool(t::E_EXPOSED, v)?;
        let v = s.req(t::E_DESCRIPTION)?;
        let description = string(&s, t::E_DESCRIPTION, v)?;
        s.finish()?;
        out.push(ListEntry {
            handle,
            env_name,
            mode,
            binding,
            exposed,
            description,
        });
    }
    d.finish()?;
    Ok(out)
}

/// `Redact{data}` request and `Redacted{data, hits}` reply. `data` ≤ 1 MiB minus framing (one frame).
pub fn encode_data(data: &[u8], hits: Option<u32>) -> Result<Vec<u8>, TlvError> {
    let mut e = enc();
    e.bytes(t::DATA, data)?;
    if let Some(h) = hits {
        e.u32(t::HITS, h)?;
    }
    Ok(done(e))
}

pub fn decode_data(b: &[u8], with_hits: bool) -> Result<(Vec<u8>, u32), TlvError> {
    let mut d = Decoder::new(b, Endian::Big)?;
    let data = d.req(t::DATA)?.to_vec();
    let hits = if with_hits {
        let v = d.req(t::HITS)?;
        d.as_u32(t::HITS, v)?
    } else {
        0
    };
    d.finish()?;
    Ok((data, hits))
}

/// An empty payload (requests without fields). Anything else is a protocol error.
pub fn expect_empty(b: &[u8]) -> Result<(), TlvError> {
    Decoder::new(b, Endian::Big)?.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn roundtrips() {
        let h = Hello {
            build_id: "b".into(),
            nonce: [3; 32],
            class: Class::Auth,
        };
        let d = Hello::decode(&h.encode().unwrap()).unwrap();
        assert_eq!(
            (d.build_id.as_str(), d.nonce, d.class),
            ("b", [3; 32], Class::Auth)
        );
        let w = Welcome {
            build_id: "b".into(),
            nonce: [1; 32],
            proof: [2; 32],
        };
        let d = Welcome::decode(&w.encode().unwrap()).unwrap();
        assert_eq!((d.nonce, d.proof), ([1; 32], [2; 32]));
        let s = StatusReply {
            pid: 7,
            ttl_left_secs: 9,
            idle_left_secs: 8,
            handles: 2,
            no_dumps: true,
            mlockall: false,
        };
        assert_eq!(StatusReply::decode(&s.encode().unwrap()).unwrap(), s);
        let l = vec![ListEntry {
            handle: "a/b".into(),
            env_name: "A_B".into(),
            mode: 2,
            binding: 0,
            exposed: false,
            description: "d".into(),
        }];
        assert_eq!(decode_list(&encode_list(&l).unwrap()).unwrap(), l);
        let e = ErrMsg {
            code: code::SEALED,
            message: "keygent: x".into(),
        };
        let d = ErrMsg::decode(&e.encode().unwrap()).unwrap();
        assert_eq!((d.code, d.message.as_str()), (code::SEALED, "keygent: x"));
    }

    #[test]
    fn rejects_bad_payloads() {
        assert!(Hello::decode(&[]).is_err());
        let mut b = Hello {
            build_id: "b".into(),
            nonce: [3; 32],
            class: Class::Hook,
        }
        .encode()
        .unwrap();
        b.extend_from_slice(&[0x7f, 0x7f, 0, 0, 0, 0]);
        assert!(Hello::decode(&b).is_err(), "unknown trailing tag");
        assert!(expect_empty(&[0, 1, 0, 0, 0, 0]).is_err());
        assert!(expect_empty(&[]).is_ok());
    }
}
