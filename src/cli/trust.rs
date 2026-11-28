//! `trust` / `untrust` (SPEC §5.6). `trust` shows the full manifest the human is trusting (read once; the same bytes
//! are hashed and recorded) and needs the passphrase. `untrust` is agent-safe: it only removes capability, so the
//! broker performs it.

use super::Args;
use super::client;
use super::cmds::{audited_commit, unlock};
use super::console::Console;
use crate::crypto::hex8;
use crate::error::{Error, Result};
use crate::platform;
use crate::policy::{manifest, render};
use crate::proto::frame::ty;
use crate::proto::msg::{Class, GrantCreate};
use crate::vault::index::TrustRec;
use crate::vault::{self, Prev};

pub fn trust(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent trust (in the project folder)"));
    }
    let d = platform::dirs()?;
    let cwd = std::env::current_dir()?;
    let m = manifest::find(&cwd).ok_or(Error::NoManifest)?;
    let entries = m.entries.clone().map_err(Error::BadManifest)?;
    let path = m.path.to_str().ok_or(Error::NoManifest)?.to_owned();
    let mut con = Console::open()?;
    con.say(&format!(
        "manifest: {path}  (sha256 {}, {} B)",
        hex8(&m.sha256),
        m.bytes.len()
    ));
    let text = String::from_utf8_lossy(&m.bytes);
    for line in text.lines() {
        con.say(&format!("  | {}", render::escape(line).0));
    }
    con.say(
        "grants, once trusted (only to commands that reference the name, and only after approval):",
    );
    for e in &entries {
        con.say(&format!(
            "  {} → ${}{}",
            e.handle,
            e.env,
            if e.file { " (file path)" } else { "" }
        ));
    }
    let l = vault::lock(&d)?;
    let mut v = unlock(&mut con, &d, &l)?;
    if v.index
        .trusted_manifests
        .iter()
        .any(|t| t.canonical_path == path && t.sha256 == m.sha256)
    {
        con.say("keygent: already trusted — nothing changed");
        return Ok(());
    }
    for e in &entries {
        if v.index.get(&e.handle).is_none() {
            con.say(&format!(
                "keygent: note: {} is not in the vault yet",
                e.handle
            ));
        }
    }
    v.index
        .trusted_manifests
        .retain(|t| t.canonical_path != path);
    v.index.trusted_manifests.push(TrustRec {
        canonical_path: path.clone(),
        sha256: m.sha256,
        trusted_at: vault::now(),
    });
    let handles: Vec<&str> = entries.iter().map(|e| e.handle.as_str()).collect();
    audited_commit(&mut v, &d, Prev::Drop, "trust", &handles)?;
    con.say(&format!("keygent: trusted {path}"));
    Ok(())
}

pub fn untrust(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent untrust (in the project folder)"));
    }
    let d = platform::dirs()?;
    let cwd = std::env::current_dir()?;
    let m = manifest::find(&cwd).ok_or(Error::NoManifest)?;
    let req = GrantCreate {
        cmd: String::new(),
        cwd: cwd.to_str().ok_or(Error::NoManifest)?.to_owned(),
        max_runtime_secs: None,
        capture: None,
    }
    .encode()
    .map_err(|_| Error::Internal(155))?;
    let mut c = client::connect(&d, Class::Run)?;
    let f = c.request(ty::UNTRUST, &req)?;
    if f.ty != ty::OK {
        return Err(Error::BrokerUnverified);
    }
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        format!("keygent: {} is no longer trusted\n", m.path.display()).as_bytes(),
    );
    Ok(())
}
