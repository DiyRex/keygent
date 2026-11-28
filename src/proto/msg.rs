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
    pub const RUN_LIMIT: u16 = 11;
    /// The audit log couldn't be written or failed verification; the message is the canonical line (exit 79).
    pub const AUDIT: u16 = 12;
    /// A human-facing failure (exit 1, e.g. a captured value too weak); the message is the canonical line.
    pub const FAILED: u16 = 13;
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

// ---------------------------------------------------------------- grants and runs (SPEC §5.5.2, §5.7)

pub const GRANT_ID_LEN: usize = 16;
/// Rendered approvals carry full script contents (≤ 16 KiB each), so they get a larger cap than `MAX_STR`.
pub const MAX_RENDERED: usize = 256 * 1024;

/// `GrantCreate{cmd, cwd, max_runtime?}` (dialect is POSIX until the PowerShell tokenizer lands).
#[derive(Debug, PartialEq, Eq)]
pub struct GrantCreate {
    pub cmd: String,
    pub cwd: String,
    pub max_runtime_secs: Option<u64>,
    /// `capture <handle>`: stdout is stored as this new handle instead of being returned (SPEC §5.9).
    pub capture: Option<String>,
}

impl GrantCreate {
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.utf8(t::CMD, &self.cmd)?;
        e.utf8(t::CWD, &self.cwd)?;
        if let Some(m) = self.max_runtime_secs {
            e.u64(t::MAX_RUNTIME, m)?;
        }
        if let Some(h) = &self.capture {
            e.utf8(t::CAPTURE, h)?;
        }
        Ok(done(e))
    }
    pub fn decode(b: &[u8]) -> Result<GrantCreate, TlvError> {
        let mut d = Decoder::new(b, Endian::Big)?;
        let v = d.req(t::CMD)?;
        if v.len() > 64 * 1024 {
            return Err(TlvError::TooLarge);
        }
        let cmd = d.as_str(t::CMD, v)?.to_owned();
        let v = d.req(t::CWD)?;
        let cwd = string(&d, t::CWD, v)?;
        let max_runtime_secs = match d.opt(t::MAX_RUNTIME)? {
            Some(v) => Some(d.as_u64(t::MAX_RUNTIME, v)?),
            None => None,
        };
        let capture = match d.opt(t::CAPTURE)? {
            Some(v) => Some(string(&d, t::CAPTURE, v)?),
            None => None,
        };
        d.finish()?;
        Ok(GrantCreate {
            cmd,
            cwd,
            max_runtime_secs,
            capture,
        })
    }
}

/// Grant states on the wire.
pub mod gstate {
    pub const PENDING: u8 = 1;
    pub const APPROVED: u8 = 2;
    pub const DENIED: u8 = 3;
    pub const EXPIRED: u8 = 4;
}

/// `GrantCreated{id, state}`, `GrantDecision{id, state}` and the requests `AwaitGrant{id}` / `Run{id}` / `Deny{id}`
/// (state omitted on requests).
pub fn encode_grant(id: &[u8; GRANT_ID_LEN], state: Option<u8>) -> Result<Vec<u8>, TlvError> {
    let mut e = enc();
    e.bytes(t::GRANT_ID, id)?;
    if let Some(s) = state {
        e.u8(t::GRANT_STATE, s)?;
    }
    Ok(done(e))
}

pub fn decode_grant(b: &[u8], with_state: bool) -> Result<([u8; GRANT_ID_LEN], u8), TlvError> {
    let mut d = Decoder::new(b, Endian::Big)?;
    let v = d.req(t::GRANT_ID)?;
    let id = d.as_array(t::GRANT_ID, v)?;
    let state = if with_state {
        let v = d.req(t::GRANT_STATE)?;
        d.as_u8(t::GRANT_STATE, v)?
    } else {
        0
    };
    d.finish()?;
    Ok((id, state))
}

/// `Deny{id | all}`.
pub fn encode_deny(id: Option<&[u8; GRANT_ID_LEN]>) -> Result<Vec<u8>, TlvError> {
    let mut e = enc();
    match id {
        Some(id) => e.bytes(t::GRANT_ID, id)?,
        None => e.bool(t::ALL, true)?,
    }
    Ok(done(e))
}

pub fn decode_deny(b: &[u8]) -> Result<Option<[u8; GRANT_ID_LEN]>, TlvError> {
    let mut d = Decoder::new(b, Endian::Big)?;
    let id = match d.opt(t::GRANT_ID)? {
        Some(v) => Some(d.as_array(t::GRANT_ID, v)?),
        None => None,
    };
    let all = match d.opt(t::ALL)? {
        Some(v) => d.as_bool(t::ALL, v)?,
        None => false,
    };
    d.finish()?;
    match (id, all) {
        (Some(id), false) => Ok(Some(id)),
        (None, true) => Ok(None),
        _ => Err(TlvError::Value(t::ALL)),
    }
}

/// One entry of `PendingReply`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PendingGrant {
    pub id: [u8; GRANT_ID_LEN],
    pub key: [u8; 32],
    pub unbound: bool,
    pub rendered: String,
}

pub fn encode_pending(list: &[PendingGrant]) -> Result<Vec<u8>, TlvError> {
    let mut e = enc();
    for g in list {
        e.nested(t::GRANT, |e| {
            e.bytes(t::GRANT_ID, &g.id)?;
            e.bytes(t::GRANT_KEY, &g.key)?;
            e.utf8(t::RENDERED, &g.rendered)?;
            e.bool(t::UNBOUND, g.unbound)
        })?;
    }
    Ok(done(e))
}

pub fn decode_pending(b: &[u8]) -> Result<Vec<PendingGrant>, TlvError> {
    let mut d = Decoder::new(b, Endian::Big)?;
    let mut out = Vec::new();
    for raw in d.list(t::GRANT)? {
        let mut s = d.sub(raw)?;
        let v = s.req(t::GRANT_ID)?;
        let id = s.as_array(t::GRANT_ID, v)?;
        let v = s.req(t::GRANT_KEY)?;
        let key = s.as_array(t::GRANT_KEY, v)?;
        let v = s.req(t::RENDERED)?;
        if v.len() > MAX_RENDERED {
            return Err(TlvError::TooLarge);
        }
        let rendered = s.as_str(t::RENDERED, v)?.to_owned();
        let v = s.req(t::UNBOUND)?;
        let unbound = s.as_bool(t::UNBOUND, v)?;
        s.finish()?;
        out.push(PendingGrant {
            id,
            key,
            unbound,
            rendered,
        });
    }
    d.finish()?;
    Ok(out)
}

/// `Approve{grant_id, grant_key, remember, proof_c}`. The proof covers `approve_request()` (SPEC §5.5.2: the human
/// approves the grant key they saw).
#[derive(Debug, PartialEq, Eq)]
pub struct Approve {
    pub id: [u8; GRANT_ID_LEN],
    pub key: [u8; 32],
    pub remember: bool,
    pub proof: [u8; 32],
}

impl Approve {
    /// The bytes `proof_c` binds: everything in the frame except the proof itself.
    pub fn request_bytes(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.bytes(t::GRANT_ID, &self.id)?;
        e.bytes(t::GRANT_KEY, &self.key)?;
        e.bool(t::REMEMBER, self.remember)?;
        Ok(done(e))
    }
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut e = enc();
        e.bytes(t::PROOF, &self.proof)?;
        e.bytes(t::GRANT_ID, &self.id)?;
        e.bytes(t::GRANT_KEY, &self.key)?;
        e.bool(t::REMEMBER, self.remember)?;
        Ok(done(e))
    }
    pub fn decode(b: &[u8]) -> Result<Approve, TlvError> {
        let mut d = Decoder::new(b, Endian::Big)?;
        let v = d.req(t::PROOF)?;
        let proof = d.as_array(t::PROOF, v)?;
        let v = d.req(t::GRANT_ID)?;
        let id = d.as_array(t::GRANT_ID, v)?;
        let v = d.req(t::GRANT_KEY)?;
        let key = d.as_array(t::GRANT_KEY, v)?;
        let v = d.req(t::REMEMBER)?;
        let remember = d.as_bool(t::REMEMBER, v)?;
        d.finish()?;
        Ok(Approve {
            id,
            key,
            remember,
            proof,
        })
    }
}

/// `Exit{code}` (128 + n for a signal, 74 for a limit) and client `Signal{n}`.
pub fn encode_u32(tag: u16, v: u32) -> Result<Vec<u8>, TlvError> {
    let mut e = enc();
    e.u32(tag, v)?;
    Ok(done(e))
}

pub fn decode_u32(b: &[u8], tag: u16) -> Result<u32, TlvError> {
    let mut d = Decoder::new(b, Endian::Big)?;
    let v = d.req(tag)?;
    let x = d.as_u32(tag, v)?;
    d.finish()?;
    Ok(x)
}

/// An empty payload (requests without fields). Anything else is a protocol error.
pub fn expect_empty(b: &[u8]) -> Result<(), TlvError> {
    Decoder::new(b, Endian::Big)?.finish()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: a panic is the failure report")]
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
    fn grant_roundtrips() {
        let g = GrantCreate {
            cmd: "X={{keygent:a}} t".into(),
            cwd: "/p".into(),
            max_runtime_secs: Some(60),
            capture: Some("new/tok".into()),
        };
        assert_eq!(GrantCreate::decode(&g.encode().unwrap()).unwrap(), g);
        let id = [7; GRANT_ID_LEN];
        assert_eq!(
            decode_grant(&encode_grant(&id, Some(gstate::APPROVED)).unwrap(), true).unwrap(),
            (id, gstate::APPROVED)
        );
        assert_eq!(
            decode_deny(&encode_deny(Some(&id)).unwrap()).unwrap(),
            Some(id)
        );
        assert_eq!(decode_deny(&encode_deny(None).unwrap()).unwrap(), None);
        assert!(decode_deny(&[]).is_err(), "deny needs an id or all");
        let p = vec![PendingGrant {
            id,
            key: [9; 32],
            unbound: true,
            rendered: "r".into(),
        }];
        assert_eq!(decode_pending(&encode_pending(&p).unwrap()).unwrap(), p);
        let a = Approve {
            id,
            key: [1; 32],
            remember: false,
            proof: [2; 32],
        };
        assert_eq!(Approve::decode(&a.encode().unwrap()).unwrap(), a);
        assert_eq!(
            decode_u32(&encode_u32(t::EXIT_CODE, 74).unwrap(), t::EXIT_CODE).unwrap(),
            74
        );
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
