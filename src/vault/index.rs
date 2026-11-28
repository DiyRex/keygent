//! Encrypted index, plaintext form (FORMATS §2): canonical little-endian TLV, `index_version` 1.
//!
//! The index can hold secret bytes (`previous_value`, kept 24 h after a rotate, SPEC §5.2), so it never derives
//! `Debug`/`Clone`, and its encoded form is a zeroizing buffer. Decoding is total and rejects unknown tags.

use crate::crypto::Secret;
use crate::error::{Error, Result};
use crate::proto::tags as t;
use crate::proto::tlv::{Decoder, Encoder, Endian, TlvError};
use zeroize::Zeroizing;

pub const INDEX_VERSION: u16 = 1;
pub const PREVIOUS_KEEP_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Binding {
    Env = 0,
    File = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Mode {
    Allow = 0,
    Confirm = 1,
    Approve = 2,
    Deny = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    Human = 0,
    Capture = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Argv {
    Deny = 0,
    Allow = 1,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Home {
    Inherit = 0,
    Scratch = 1,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "allow" => Mode::Allow,
            "confirm" => Mode::Confirm,
            "approve" => Mode::Approve,
            "deny" => Mode::Deny,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Mode::Allow => "allow",
            Mode::Confirm => "confirm",
            Mode::Approve => "approve",
            Mode::Deny => "deny",
        }
    }
}

impl Binding {
    pub fn name(self) -> &'static str {
        match self {
            Binding::Env => "env",
            Binding::File => "file",
        }
    }
}

impl Argv {
    pub fn name(self) -> &'static str {
        match self {
            Argv::Deny => "deny",
            Argv::Allow => "allow",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Flag {
    pub name: String,
    pub takes_value: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AllowRule {
    pub exe: String,
    pub sha256: [u8; 32],
    pub args: Vec<String>,
    pub flags: Vec<Flag>,
    pub home: Home,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfigSeen {
    pub tool: String,
    pub path: String,
    pub sha256: [u8; 32],
    pub approved_at: u64,
}

pub struct HandleRec {
    pub handle: String,
    pub env_name: String,
    pub description: String,
    pub binding: Binding,
    pub mode: Mode,
    pub allow_rules: Vec<AllowRule>,
    pub hosts: Vec<String>,
    pub created_at: u64,
    pub rotated_at: u64,
    pub version: u32,
    pub previous_version_until: Option<u64>,
    pub exposed: bool,
    pub origin: Origin,
    pub argv: Argv,
    pub config_seen: Vec<ConfigSeen>,
    pub previous_value: Option<Secret>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TrustRec {
    pub canonical_path: String,
    pub sha256: [u8; 32],
    pub trusted_at: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PasskeyRec {
    pub credential_id: Vec<u8>,
    pub cose_pubkey: Vec<u8>,
    pub sign_count: u32,
    pub label: String,
    pub created_at: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ShellPaths {
    pub posix: Option<String>,
    pub git_bash: Option<String>,
    pub pwsh: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Security {
    pub ttl_max_secs: u32,
    pub idle_secs: u32,
    pub run_max_minutes: u32,
    pub remember_enabled: bool,
    pub default_mode: Mode,
}

/// SPEC §4.1 defaults.
pub const SECURITY_DEFAULT: Security = Security {
    ttl_max_secs: 8 * 3600,
    idle_secs: 30 * 60,
    run_max_minutes: 30,
    remember_enabled: true,
    default_mode: Mode::Approve,
};

/// Hard ceilings for security settings (SPEC §4.1): TTL ≤ 24 h, run ≤ 4 h.
pub const TTL_MAX_CEILING: u32 = 24 * 3600;
pub const RUN_MAX_CEILING_MIN: u32 = 4 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuditAnchor {
    pub seq: u64,
    pub mac: [u8; 32],
}

pub struct Index {
    pub handles: Vec<HandleRec>,
    pub trusted_manifests: Vec<TrustRec>,
    pub passkeys: Vec<PasskeyRec>,
    pub shell_paths: ShellPaths,
    pub ui_binary_sha256: Option<[u8; 32]>,
    pub security: Security,
    pub audit_anchor: Option<AuditAnchor>,
    pub tripwire_id: [u8; 16],
}

impl Index {
    pub fn new(tripwire_id: [u8; 16]) -> Self {
        Index {
            handles: Vec::new(),
            trusted_manifests: Vec::new(),
            passkeys: Vec::new(),
            shell_paths: ShellPaths::default(),
            ui_binary_sha256: None,
            security: SECURITY_DEFAULT,
            audit_anchor: None,
            tripwire_id,
        }
    }

    pub fn get(&self, h: &str) -> Option<&HandleRec> {
        self.handles.iter().find(|r| r.handle == h)
    }

    pub fn get_mut(&mut self, h: &str) -> Option<&mut HandleRec> {
        self.handles.iter_mut().find(|r| r.handle == h)
    }

    /// Drop previous values older than 24 h (SPEC §5.2). Returns true if anything was dropped.
    pub fn expire_previous(&mut self, now: u64) -> bool {
        let mut changed = false;
        for r in &mut self.handles {
            if r.previous_version_until.is_some_and(|u| u <= now) {
                r.previous_version_until = None;
                r.previous_value = None;
                changed = true;
            }
        }
        changed
    }

    /// Canonical encoding. Handles are written sorted by name so the encoding is deterministic.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.encode_inner()
            .map_err(|_| Error::TooLarge("16 MiB index"))
    }

    fn encode_inner(&self) -> std::result::Result<Zeroizing<Vec<u8>>, TlvError> {
        let mut e = Encoder::new(Endian::Little);
        e.u16(t::index::INDEX_VERSION, INDEX_VERSION)?;
        let mut hs: Vec<&HandleRec> = self.handles.iter().collect();
        hs.sort_by(|a, b| a.handle.cmp(&b.handle));
        for h in hs {
            e.nested(t::index::HANDLE, |e| enc_handle(e, h))?;
        }
        for m in &self.trusted_manifests {
            e.nested(t::index::TRUSTED_MANIFEST, |e| {
                e.utf8(t::trusted_manifest::CANONICAL_PATH, &m.canonical_path)?;
                e.bytes(t::trusted_manifest::SHA256, &m.sha256)?;
                e.u64(t::trusted_manifest::TRUSTED_AT, m.trusted_at)
            })?;
        }
        for p in &self.passkeys {
            e.nested(t::index::PASSKEY, |e| {
                e.bytes(t::passkey::CREDENTIAL_ID, &p.credential_id)?;
                e.bytes(t::passkey::COSE_PUBKEY, &p.cose_pubkey)?;
                e.u32(t::passkey::SIGN_COUNT, p.sign_count)?;
                e.utf8(t::passkey::LABEL, &p.label)?;
                e.u64(t::passkey::CREATED_AT, p.created_at)
            })?;
        }
        let sp = &self.shell_paths;
        e.nested(t::index::SHELL_PATHS, |e| {
            for (tag, v) in [
                (t::shell_paths::POSIX, &sp.posix),
                (t::shell_paths::GIT_BASH, &sp.git_bash),
                (t::shell_paths::PWSH, &sp.pwsh),
            ] {
                if let Some(v) = v {
                    e.utf8(tag, v)?;
                }
            }
            Ok(())
        })?;
        if let Some(h) = &self.ui_binary_sha256 {
            e.bytes(t::index::UI_BINARY_SHA256, h)?;
        }
        let s = self.security;
        e.nested(t::index::SECURITY_SETTINGS, |e| {
            e.u32(t::security::TTL_MAX, s.ttl_max_secs)?;
            e.u32(t::security::IDLE, s.idle_secs)?;
            e.u32(t::security::RUN_MAX_MINUTES, s.run_max_minutes)?;
            e.bool(t::security::REMEMBER_ENABLED, s.remember_enabled)?;
            e.u8(t::security::DEFAULT_MODE, s.default_mode as u8)
        })?;
        if let Some(a) = &self.audit_anchor {
            e.nested(t::index::AUDIT_ANCHOR, |e| {
                e.u64(t::audit_anchor::SEQ, a.seq)?;
                e.bytes(t::audit_anchor::MAC, &a.mac)
            })?;
        }
        e.bytes(t::index::TRIPWIRE_ID, &self.tripwire_id)?;
        Ok(e.finish())
    }

    pub fn decode(b: &[u8]) -> Result<Index> {
        decode_inner(b).map_err(|_| Error::Damaged)
    }
}

fn enc_handle(e: &mut Encoder, h: &HandleRec) -> std::result::Result<(), TlvError> {
    use t::handle as th;
    e.utf8(th::HANDLE, &h.handle)?;
    e.utf8(th::ENV_NAME, &h.env_name)?;
    e.utf8(th::DESCRIPTION, &h.description)?;
    e.u8(th::BINDING, h.binding as u8)?;
    e.u8(th::MODE, h.mode as u8)?;
    for r in &h.allow_rules {
        e.nested(th::ALLOW_RULE, |e| {
            e.utf8(t::allow_rule::EXE, &r.exe)?;
            e.bytes(t::allow_rule::SHA256, &r.sha256)?;
            for a in &r.args {
                e.utf8(t::allow_rule::ARG, a)?;
            }
            for f in &r.flags {
                e.nested(t::allow_rule::FLAG, |e| {
                    e.utf8(t::flag::NAME, &f.name)?;
                    e.bool(t::flag::TAKES_VALUE, f.takes_value)
                })?;
            }
            e.u8(t::allow_rule::HOME, r.home as u8)
        })?;
    }
    for host in &h.hosts {
        e.utf8(th::HOST, host)?;
    }
    e.u64(th::CREATED_AT, h.created_at)?;
    e.u64(th::ROTATED_AT, h.rotated_at)?;
    e.u32(th::VERSION, h.version)?;
    if let Some(u) = h.previous_version_until {
        e.u64(th::PREVIOUS_VERSION_UNTIL, u)?;
    }
    e.bool(th::EXPOSED, h.exposed)?;
    e.u8(th::ORIGIN, h.origin as u8)?;
    e.u8(th::ARGV, h.argv as u8)?;
    for c in &h.config_seen {
        e.nested(th::CONFIG_SEEN, |e| {
            e.utf8(t::config_seen::TOOL, &c.tool)?;
            e.utf8(t::config_seen::PATH, &c.path)?;
            e.bytes(t::config_seen::SHA256, &c.sha256)?;
            e.u64(t::config_seen::APPROVED_AT, c.approved_at)
        })?;
    }
    if let Some(p) = &h.previous_value {
        e.bytes(th::PREVIOUS_VALUE, p.expose())?;
    }
    Ok(())
}

fn enum_u8<T>(
    d: &Decoder<'_>,
    tag: u16,
    v: &[u8],
    f: impl Fn(u8) -> Option<T>,
) -> std::result::Result<T, TlvError> {
    f(d.as_u8(tag, v)?).ok_or(TlvError::Value(tag))
}

fn mode(b: u8) -> Option<Mode> {
    Some(match b {
        0 => Mode::Allow,
        1 => Mode::Confirm,
        2 => Mode::Approve,
        3 => Mode::Deny,
        _ => return None,
    })
}

fn decode_handle(d: &mut Decoder<'_>) -> std::result::Result<HandleRec, TlvError> {
    use t::handle as th;
    let v = d.req(th::HANDLE)?;
    let handle = d.as_str(th::HANDLE, v)?.to_owned();
    let v = d.req(th::ENV_NAME)?;
    let env_name = d.as_str(th::ENV_NAME, v)?.to_owned();
    let v = d.req(th::DESCRIPTION)?;
    let description = d.as_str(th::DESCRIPTION, v)?.to_owned();
    let v = d.req(th::BINDING)?;
    let binding = enum_u8(d, th::BINDING, v, |b| match b {
        0 => Some(Binding::Env),
        1 => Some(Binding::File),
        _ => None,
    })?;
    let v = d.req(th::MODE)?;
    let mode = enum_u8(d, th::MODE, v, mode)?;
    let mut allow_rules = Vec::new();
    for raw in d.list(th::ALLOW_RULE)? {
        let mut r = d.sub(raw)?;
        let v = r.req(t::allow_rule::EXE)?;
        let exe = r.as_str(t::allow_rule::EXE, v)?.to_owned();
        let v = r.req(t::allow_rule::SHA256)?;
        let sha256 = r.as_array(t::allow_rule::SHA256, v)?;
        let mut args = Vec::new();
        for a in r.list(t::allow_rule::ARG)? {
            args.push(r.as_str(t::allow_rule::ARG, a)?.to_owned());
        }
        let mut flags = Vec::new();
        for f in r.list(t::allow_rule::FLAG)? {
            let mut fd = r.sub(f)?;
            let v = fd.req(t::flag::NAME)?;
            let name = fd.as_str(t::flag::NAME, v)?.to_owned();
            let v = fd.req(t::flag::TAKES_VALUE)?;
            let takes_value = fd.as_bool(t::flag::TAKES_VALUE, v)?;
            fd.finish()?;
            flags.push(Flag { name, takes_value });
        }
        let v = r.req(t::allow_rule::HOME)?;
        let home = enum_u8(&r, t::allow_rule::HOME, v, |b| match b {
            0 => Some(Home::Inherit),
            1 => Some(Home::Scratch),
            _ => None,
        })?;
        r.finish()?;
        allow_rules.push(AllowRule {
            exe,
            sha256,
            args,
            flags,
            home,
        });
    }
    let mut hosts = Vec::new();
    for h in d.list(th::HOST)? {
        hosts.push(d.as_str(th::HOST, h)?.to_owned());
    }
    let v = d.req(th::CREATED_AT)?;
    let created_at = d.as_u64(th::CREATED_AT, v)?;
    let v = d.req(th::ROTATED_AT)?;
    let rotated_at = d.as_u64(th::ROTATED_AT, v)?;
    let v = d.req(th::VERSION)?;
    let version = d.as_u32(th::VERSION, v)?;
    let previous_version_until = match d.opt(th::PREVIOUS_VERSION_UNTIL)? {
        Some(v) => Some(d.as_u64(th::PREVIOUS_VERSION_UNTIL, v)?),
        None => None,
    };
    let v = d.req(th::EXPOSED)?;
    let exposed = d.as_bool(th::EXPOSED, v)?;
    let v = d.req(th::ORIGIN)?;
    let origin = enum_u8(d, th::ORIGIN, v, |b| match b {
        0 => Some(Origin::Human),
        1 => Some(Origin::Capture),
        _ => None,
    })?;
    let v = d.req(th::ARGV)?;
    let argv = enum_u8(d, th::ARGV, v, |b| match b {
        0 => Some(Argv::Deny),
        1 => Some(Argv::Allow),
        _ => None,
    })?;
    let mut config_seen = Vec::new();
    for c in d.list(th::CONFIG_SEEN)? {
        let mut cd = d.sub(c)?;
        let v = cd.req(t::config_seen::TOOL)?;
        let tool = cd.as_str(t::config_seen::TOOL, v)?.to_owned();
        let v = cd.req(t::config_seen::PATH)?;
        let path = cd.as_str(t::config_seen::PATH, v)?.to_owned();
        let v = cd.req(t::config_seen::SHA256)?;
        let sha256 = cd.as_array(t::config_seen::SHA256, v)?;
        let v = cd.req(t::config_seen::APPROVED_AT)?;
        let approved_at = cd.as_u64(t::config_seen::APPROVED_AT, v)?;
        cd.finish()?;
        config_seen.push(ConfigSeen {
            tool,
            path,
            sha256,
            approved_at,
        });
    }
    let previous_value = d.opt(th::PREVIOUS_VALUE)?.map(Secret::from_slice);
    if previous_value.is_some() != previous_version_until.is_some() {
        return Err(TlvError::Shape(th::PREVIOUS_VALUE));
    }
    Ok(HandleRec {
        handle,
        env_name,
        description,
        binding,
        mode,
        allow_rules,
        hosts,
        created_at,
        rotated_at,
        version,
        previous_version_until,
        exposed,
        origin,
        argv,
        config_seen,
        previous_value,
    })
}

fn decode_inner(b: &[u8]) -> std::result::Result<Index, TlvError> {
    let mut d = Decoder::new(b, Endian::Little)?;
    let v = d.req(t::index::INDEX_VERSION)?;
    if d.as_u16(t::index::INDEX_VERSION, v)? != INDEX_VERSION {
        return Err(TlvError::Value(t::index::INDEX_VERSION));
    }
    let raw_handles = d.list(t::index::HANDLE)?;
    if raw_handles.len() > super::names::MAX_HANDLES {
        return Err(TlvError::TooLarge);
    }
    let mut handles: Vec<HandleRec> = Vec::with_capacity(raw_handles.len());
    for raw in raw_handles {
        let mut hd = d.sub(raw)?;
        let h = decode_handle(&mut hd)?;
        hd.finish()?;
        // canonical: strictly ascending, so no duplicates
        if handles.last().is_some_and(|p| p.handle >= h.handle) {
            return Err(TlvError::Shape(t::index::HANDLE));
        }
        handles.push(h);
    }
    let mut trusted_manifests = Vec::new();
    for raw in d.list(t::index::TRUSTED_MANIFEST)? {
        let mut m = d.sub(raw)?;
        let v = m.req(t::trusted_manifest::CANONICAL_PATH)?;
        let canonical_path = m.as_str(t::trusted_manifest::CANONICAL_PATH, v)?.to_owned();
        let v = m.req(t::trusted_manifest::SHA256)?;
        let sha256 = m.as_array(t::trusted_manifest::SHA256, v)?;
        let v = m.req(t::trusted_manifest::TRUSTED_AT)?;
        let trusted_at = m.as_u64(t::trusted_manifest::TRUSTED_AT, v)?;
        m.finish()?;
        trusted_manifests.push(TrustRec {
            canonical_path,
            sha256,
            trusted_at,
        });
    }
    let mut passkeys = Vec::new();
    for raw in d.list(t::index::PASSKEY)? {
        let mut p = d.sub(raw)?;
        let credential_id = p.req(t::passkey::CREDENTIAL_ID)?.to_vec();
        let cose_pubkey = p.req(t::passkey::COSE_PUBKEY)?.to_vec();
        let v = p.req(t::passkey::SIGN_COUNT)?;
        let sign_count = p.as_u32(t::passkey::SIGN_COUNT, v)?;
        let v = p.req(t::passkey::LABEL)?;
        let label = p.as_str(t::passkey::LABEL, v)?.to_owned();
        let v = p.req(t::passkey::CREATED_AT)?;
        let created_at = p.as_u64(t::passkey::CREATED_AT, v)?;
        p.finish()?;
        passkeys.push(PasskeyRec {
            credential_id,
            cose_pubkey,
            sign_count,
            label,
            created_at,
        });
    }
    let v = d.req(t::index::SHELL_PATHS)?;
    let mut s = d.sub(v)?;
    let opt_str = |s: &mut Decoder<'_>, tag| -> std::result::Result<Option<String>, TlvError> {
        Ok(match s.opt(tag)? {
            Some(v) => Some(s.as_str(tag, v)?.to_owned()),
            None => None,
        })
    };
    let shell_paths = ShellPaths {
        posix: opt_str(&mut s, t::shell_paths::POSIX)?,
        git_bash: opt_str(&mut s, t::shell_paths::GIT_BASH)?,
        pwsh: opt_str(&mut s, t::shell_paths::PWSH)?,
    };
    s.finish()?;
    let ui_binary_sha256 = match d.opt(t::index::UI_BINARY_SHA256)? {
        Some(v) => Some(d.as_array(t::index::UI_BINARY_SHA256, v)?),
        None => None,
    };
    let v = d.req(t::index::SECURITY_SETTINGS)?;
    let mut sd = d.sub(v)?;
    let v = sd.req(t::security::TTL_MAX)?;
    let ttl_max_secs = sd.as_u32(t::security::TTL_MAX, v)?;
    let v = sd.req(t::security::IDLE)?;
    let idle_secs = sd.as_u32(t::security::IDLE, v)?;
    let v = sd.req(t::security::RUN_MAX_MINUTES)?;
    let run_max_minutes = sd.as_u32(t::security::RUN_MAX_MINUTES, v)?;
    let v = sd.req(t::security::REMEMBER_ENABLED)?;
    let remember_enabled = sd.as_bool(t::security::REMEMBER_ENABLED, v)?;
    let v = sd.req(t::security::DEFAULT_MODE)?;
    let default_mode = enum_u8(&sd, t::security::DEFAULT_MODE, v, mode)?;
    sd.finish()?;
    if ttl_max_secs > TTL_MAX_CEILING || run_max_minutes > RUN_MAX_CEILING_MIN {
        return Err(TlvError::Value(t::index::SECURITY_SETTINGS));
    }
    let audit_anchor = match d.opt(t::index::AUDIT_ANCHOR)? {
        Some(v) => {
            let mut a = d.sub(v)?;
            let s = a.req(t::audit_anchor::SEQ)?;
            let seq = a.as_u64(t::audit_anchor::SEQ, s)?;
            let m = a.req(t::audit_anchor::MAC)?;
            let mac = a.as_array(t::audit_anchor::MAC, m)?;
            a.finish()?;
            Some(AuditAnchor { seq, mac })
        }
        None => None,
    };
    let v = d.req(t::index::TRIPWIRE_ID)?;
    let tripwire_id = d.as_array(t::index::TRIPWIRE_ID, v)?;
    d.finish()?;
    Ok(Index {
        handles,
        trusted_manifests,
        passkeys,
        shell_paths,
        ui_binary_sha256,
        security: Security {
            ttl_max_secs,
            idle_secs,
            run_max_minutes,
            remember_enabled,
            default_mode,
        },
        audit_anchor,
        tripwire_id,
    })
}

/// A fresh handle record with SPEC defaults (mode from the security settings, argv deny, env binding).
pub fn new_handle(
    handle: &str,
    env_name: &str,
    description: &str,
    default_mode: Mode,
    now: u64,
) -> HandleRec {
    HandleRec {
        handle: handle.to_owned(),
        env_name: env_name.to_owned(),
        description: description.to_owned(),
        binding: Binding::Env,
        mode: default_mode,
        allow_rules: Vec::new(),
        hosts: Vec::new(),
        created_at: now,
        rotated_at: now,
        version: 1,
        previous_version_until: None,
        exposed: false,
        origin: Origin::Human,
        argv: Argv::Deny,
        config_seen: Vec::new(),
        previous_value: None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    pub(crate) fn sample() -> Index {
        let mut i = Index::new([7u8; 16]);
        let mut h = new_handle(
            "stripe/live",
            "STRIPE_API_KEY",
            "Stripe live key",
            Mode::Approve,
            1_700_000_000,
        );
        h.allow_rules.push(AllowRule {
            exe: "/opt/homebrew/bin/stripe".into(),
            sha256: [1u8; 32],
            args: vec!["customers".into(), "*".into()],
            flags: vec![Flag {
                name: "--limit".into(),
                takes_value: true,
            }],
            home: Home::Inherit,
        });
        h.hosts.push("api.stripe.com".into());
        h.previous_version_until = Some(1_700_086_400);
        h.previous_value = Some(Secret::from_slice(b"KEYGENT_CANARY_previous"));
        i.handles.push(h);
        i.handles
            .push(new_handle("a/first", "A_FIRST", "", Mode::Deny, 1));
        i.trusted_manifests.push(TrustRec {
            canonical_path: "/p/.keygent.toml".into(),
            sha256: [2u8; 32],
            trusted_at: 5,
        });
        i.shell_paths.posix = Some("/bin/sh".into());
        i.audit_anchor = Some(AuditAnchor {
            seq: 3,
            mac: [4u8; 32],
        });
        i
    }

    #[test]
    fn roundtrip_and_canonical() {
        let i = sample();
        let b = i.encode().unwrap();
        let d = Index::decode(&b).unwrap();
        assert_eq!(d.handles.len(), 2);
        assert_eq!(d.handles[0].handle, "a/first"); // sorted
        let s = d.get("stripe/live").unwrap();
        assert_eq!(s.allow_rules, i.get("stripe/live").unwrap().allow_rules);
        assert_eq!(
            s.previous_value.as_ref().unwrap().expose(),
            b"KEYGENT_CANARY_previous"
        );
        assert_eq!(d.shell_paths.posix.as_deref(), Some("/bin/sh"));
        assert_eq!(d.audit_anchor, i.audit_anchor);
        // re-encoding a decoded index is byte-identical
        assert_eq!(*d.encode().unwrap(), *b);
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        let b = sample().encode().unwrap();
        for n in [0, 1, 5, 6, b.len() / 2, b.len() - 1] {
            assert!(Index::decode(&b[..n]).is_err(), "{n}");
        }
        let mut x = b.to_vec();
        x.extend_from_slice(&[0xff, 0x7f, 0, 0, 0, 0]);
        assert!(Index::decode(&x).is_err());
    }

    #[test]
    fn expire_previous_values() {
        let mut i = sample();
        assert!(!i.expire_previous(1_700_000_000));
        assert!(i.expire_previous(1_700_086_400));
        assert!(i.get("stripe/live").unwrap().previous_value.is_none());
    }
}
