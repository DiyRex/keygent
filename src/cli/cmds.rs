//! Phase 1 command handlers (SPEC §5.1, §5.2). While sealed, the CLI writes the vault directly under the lock
//! (SPEC §5.2 "Who writes"); every mutation needs the passphrase typed on the terminal (auth is the gate, SPEC §5.5.1).
//!
//! Output rules: human confirmations go to the terminal, never stdout; values appear only via the alternate screen
//! (`reveal`, and the one-time display of a new passphrase or recovery key). Errors are one `keygent:` line.

use super::console::{Console, MAX_SECRET_INPUT};
use super::{Args, dotenv, recovery};
use crate::crypto::{self, Secret};
use crate::error::{Error, Result};
use crate::platform::{self, Dirs, Platform};
use crate::vault::index::{self, Argv, Binding, Index, Mode};
use crate::vault::{self, Lock, Prev, Unlock, Vault, audit, format, names, strength};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

const PASSPHRASE_WORDS: usize = 6;
const REVEAL_SECS: u64 = 20;
const COPY_SECS: u64 = 10;
const AUTH_ATTEMPTS: usize = 3;

/// Append the audit record, anchor it in the index, then commit (SPEC §9: anchored on every vault write). An audit
/// failure leaves the vault unchanged.
pub(super) fn audited_commit(
    v: &mut Vault,
    d: &Dirs,
    prev: Prev,
    event: &'static str,
    handles: &[&str],
) -> Result<()> {
    let mut r = audit::Record::new(event);
    r.handles = handles.iter().map(|h| (*h).to_owned()).collect();
    r.channel = Some("terminal");
    let (seq, mac) = audit::append(d, &v.audit_key()?, &r)?;
    v.index.audit_anchor = Some(index::AuditAnchor { seq, mac });
    v.commit(prev)
}

fn dirs() -> Result<Dirs> {
    platform::dirs()
}

/// Factor changes and restores first seal a running broker and wait for it to exit (SPEC §5.2, ADR 0012).
fn seal_broker(d: &Dirs) -> Result<()> {
    #[cfg(unix)]
    if super::client::seal_if_running(d)? {
        let _ = writeln!(
            std::io::stderr(),
            "keygent: sealed the running broker first — run 'keygent unseal' afterwards"
        );
    }
    #[cfg(not(unix))]
    let _ = d;
    Ok(())
}

fn one_handle(a: &Args, usage: &'static str) -> Result<String> {
    match a.pos.as_slice() {
        [h] => {
            names::check_handle(h)?;
            Ok(h.clone())
        }
        _ => Err(Error::Usage(usage)),
    }
}

/// Ask for the passphrase (3 attempts) and open the vault. A rolled-back vault needs an explicit confirmation.
pub(super) fn unlock_vault(con: &mut Console, d: &Dirs, l: &Lock) -> Result<Vault> {
    unlock(con, d, l)
}

pub(super) fn unlock(con: &mut Console, d: &Dirs, l: &Lock) -> Result<Vault> {
    if !Vault::exists(d) {
        return Err(Error::NoVault);
    }
    let mut last = Error::WrongPassphrase;
    for _ in 0..AUTH_ATTEMPTS {
        let p = con.read_hidden("Passphrase: ")?;
        match Vault::open(d, l, Unlock::Passphrase(&p)) {
            Ok(v) => return confirm_rollback(con, v),
            Err(Error::WrongPassphrase) => {
                con.say("keygent: wrong passphrase");
                last = Error::WrongPassphrase;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

fn confirm_rollback(con: &mut Console, v: Vault) -> Result<Vault> {
    if v.rolled_back {
        con.say("keygent: vault is older than expected (rolled back?) — confirm to continue");
        if !con.confirm("Continue with this older vault?")? {
            return Err(Error::RolledBack);
        }
    }
    Ok(v)
}

fn generate_passphrase() -> Result<Secret> {
    let words = strength::eff_words();
    let n = u32::try_from(words.len()).map_err(|_| Error::Internal(60))?;
    let mut s = Zeroizing::new(String::with_capacity(PASSPHRASE_WORDS * 10));
    for i in 0..PASSPHRASE_WORDS {
        if i > 0 {
            s.push('-');
        }
        let w =
            words.get(usize::try_from(crypto::random_below(n)?).map_err(|_| Error::Internal(61))?);
        s.push_str(w.ok_or(Error::Internal(62))?);
    }
    Ok(Secret::from_slice(s.as_bytes()))
}

/// A new passphrase: generated (default, shown once and typed back) or the user's own (checked, typed twice).
fn new_passphrase(con: &mut Console, own: bool) -> Result<Secret> {
    if own {
        let p = con.read_hidden("New passphrase (16+ chars, 5+ random words): ")?;
        strength::check_passphrase(p.expose())?;
        let again = con.read_hidden("Repeat it: ")?;
        if !p.ct_eq(again.expose()) {
            return Err(Error::Mismatch);
        }
        return Ok(p);
    }
    let p = generate_passphrase()?;
    con.show_secret(
        "Your new keygent passphrase (6 random words). Write it down; it is shown only once.",
        p.expose(),
        Duration::from_secs(300),
    )?;
    let typed = con.read_hidden("Type the passphrase back to confirm: ")?;
    if !p.ct_eq(typed.expose()) {
        return Err(Error::Mismatch);
    }
    Ok(p)
}

/// A new recovery key, shown once and typed back (SPEC §5.2).
fn new_recovery_key(con: &mut Console) -> Result<Secret> {
    let rk = recovery::generate()?;
    let shown = recovery::encode(&rk)?;
    con.show_secret(
        "Your recovery key. Store it offline; it is the only way back if you forget the passphrase.",
        shown.as_bytes(),
        Duration::from_secs(300),
    )?;
    let typed = con.read_hidden("Type the recovery key back to confirm: ")?;
    let back = recovery::decode(typed.expose()).map_err(|_| Error::Mismatch)?;
    if !rk.ct_eq(back.expose()) {
        return Err(Error::Mismatch);
    }
    Ok(rk)
}

fn read_recovery_key(con: &mut Console) -> Result<Secret> {
    let typed = con.read_hidden("Recovery key: ")?;
    recovery::decode(typed.expose())
}

/// Read a secret value per the input flags. Returns the source file to offer deletion for.
fn read_value(con: &mut Console, a: &Args) -> Result<(Secret, Option<PathBuf>)> {
    if a.has("--multiline") && a.has("--from-file") {
        return Err(Error::Usage("use either --multiline or --from-file"));
    }
    if a.has("--delete") && !a.has("--from-file") {
        return Err(Error::Usage("--delete needs --from-file"));
    }
    if let Some(p) = a.value("--from-file") {
        let path = PathBuf::from(p);
        return Ok((read_input_file(&path, MAX_SECRET_INPUT)?, Some(path)));
    }
    let v = if a.has("--multiline") {
        con.read_multiline_hidden("Paste the value, then a line with only '.':")?
    } else {
        con.read_hidden("Value: ")?
    };
    Ok((v, None))
}

/// A user-supplied input file: regular, owned by the user, no symlink, size-capped before reading. Its path is never
/// printed or logged.
fn read_input_file(path: &Path, cap: usize) -> Result<Secret> {
    let f = platform::os().open_user_input(path)?;
    let len = usize::try_from(f.metadata()?.len()).map_err(|_| Error::ValueSize)?;
    if len > cap {
        return Err(Error::ValueSize);
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(cap.saturating_add(1)));
    f.take(u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() > cap {
        return Err(Error::ValueSize);
    }
    Ok(Secret::new(buf.to_vec()))
}

fn maybe_delete_source(con: &mut Console, src: Option<PathBuf>, always: bool) -> Result<()> {
    let Some(p) = src else { return Ok(()) };
    if always || con.confirm("Delete the source file now?")? {
        std::fs::remove_file(&p)?;
        con.say("keygent: source file deleted (on SSD/APFS the old blocks may linger)");
    }
    Ok(())
}

fn check_new_handle(ix: &Index, h: &str) -> Result<()> {
    if ix.get(h).is_some() {
        return Err(Error::Exists(h.to_owned()));
    }
    if let Some(other) = names::collision(h, ix.handles.iter().map(|r| r.handle.as_str())) {
        return Err(Error::Collision(other.to_owned()));
    }
    if ix.handles.len() >= names::MAX_HANDLES {
        return Err(Error::TooLarge("1000 secrets"));
    }
    Ok(())
}

/// SPEC §5.8: refuse a write that would push the redactor past its 8 MiB pattern cap (current and previous values of
/// every handle, plus `new` values). Checked here so `unseal` never has to refuse the vault later.
fn check_redactor_cap(v: &Vault, new: &[&[u8]]) -> Result<()> {
    let mut total = 0usize;
    for r in &v.index.handles {
        total = total.saturating_add(crate::redact::pattern_bytes(
            v.read_entry(&r.handle)?.expose(),
        ));
        if let Some(p) = &r.previous_value {
            total = total.saturating_add(crate::redact::pattern_bytes(p.expose()));
        }
    }
    for n in new {
        total = total.saturating_add(crate::redact::pattern_bytes(n));
    }
    if total > crate::redact::MAX_PATTERN_BYTES {
        return Err(Error::RedactorTooLarge);
    }
    Ok(())
}

fn check_description(d: &str) -> Result<()> {
    if d.chars().count() > names::MAX_DESCRIPTION_CHARS || d.chars().any(char::is_control) {
        return Err(Error::Usage(
            "--description: up to 200 chars, no control characters",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- vault commands

pub fn init(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent init [--own-passphrase]"));
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    if Vault::exists(&d) {
        return Err(Error::VaultExists);
    }
    let mut con = Console::open()?;
    let pass = new_passphrase(&mut con, a.has("--own-passphrase"))?;
    let rk = new_recovery_key(&mut con)?;
    let mut v = Vault::create(&d, &l, &pass, &rk)?;
    v.commit(Prev::Keep)?;
    con.say("keygent: vault created");
    Ok(())
}

pub fn passwd(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent passwd [--own-passphrase]"));
    }
    let d = dirs()?;
    seal_broker(&d)?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    let pass = new_passphrase(&mut con, a.has("--own-passphrase"))?;
    let pepper = v.keystore().pepper()?.ok_or(Error::PepperMissing)?;
    v.set_passphrase(&pass, &pepper)?;
    v.commit(Prev::Drop)?;
    con.say("keygent: passphrase changed (old backups still open with the old one)");
    Ok(())
}

pub fn rekey(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent rekey"));
    }
    let d = dirs()?;
    seal_broker(&d)?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    if !Vault::exists(&d) {
        return Err(Error::NoVault);
    }
    // rekey keeps the passphrase but needs it for the new slot, so read it here rather than via unlock()
    let pass = con.read_hidden("Passphrase: ")?;
    let v = Vault::open(&d, &l, Unlock::Passphrase(&pass))?;
    let mut v = confirm_rollback(&mut con, v)?;
    con.say("keygent: rekey creates a new data key and a NEW recovery key; the old recovery key stops working");
    let rk = new_recovery_key(&mut con)?;
    v.rekey(&pass, &rk)?;
    v.commit(Prev::Drop)?;
    con.say("keygent: rekeyed (old backups still open with the old factors)");
    Ok(())
}

pub fn recover(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent recover [--own-passphrase]"));
    }
    let d = dirs()?;
    seal_broker(&d)?;
    let l = vault::lock(&d)?;
    if !Vault::exists(&d) {
        return Err(Error::NoVault);
    }
    let mut con = Console::open()?;
    let rk = read_recovery_key(&mut con)?;
    let v = Vault::open(&d, &l, Unlock::Recovery(&rk))?;
    let mut v = confirm_rollback(&mut con, v)?;
    let pass = new_passphrase(&mut con, a.has("--own-passphrase"))?;
    let rk2 = new_recovery_key(&mut con)?;
    v.rekey(&pass, &rk2)?;
    v.commit(Prev::Drop)?;
    con.say("keygent: recovered — new passphrase and new recovery key are active");
    Ok(())
}

pub fn verify(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent verify"));
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    if !Vault::exists(&d) {
        return Err(Error::NoVault);
    }
    let pass = con.read_hidden("Passphrase: ")?;
    let v = match Vault::open(&d, &l, Unlock::Passphrase(&pass)) {
        Ok(v) => v,
        Err(Error::Damaged) => {
            con.say("keygent: header or index failed verification");
            return offer_prev(&mut con, &d, &pass);
        }
        Err(e) => return Err(e),
    };
    let mut bad = 0usize;
    for r in &v.index.handles {
        match v.read_entry(&r.handle) {
            Ok(_) => con.say(&format!("  ok       {}", r.handle)),
            Err(_) => {
                bad = bad.saturating_add(1);
                con.say(&format!("  DAMAGED  {}", r.handle));
            }
        }
    }
    let orphans = v
        .file
        .entries
        .iter()
        .filter(|e| v.index.get(&e.handle).is_none())
        .count();
    if orphans > 0 {
        con.say(&format!(
            "  {orphans} unlisted entr(y/ies) will be dropped on the next write"
        ));
    }
    if v.rolled_back {
        con.say("keygent: vault is older than expected (rolled back?)");
    }
    if bad == 0 {
        con.say(&format!(
            "keygent: vault ok — header MAC, index and {} entries verified",
            v.index.handles.len()
        ));
        return Ok(());
    }
    drop(v);
    offer_prev(&mut con, &d, &pass)
}

/// Offer to restore `vault.kgt.prev` if it verifies fully with the same passphrase. The restored content is written
/// as a **new** generation, so the rollback tripwire stays consistent.
fn offer_prev(con: &mut Console, d: &Dirs, pass: &Secret) -> Result<()> {
    let prev = d.data.join(vault::PREV_FILE);
    let Some(bytes) = vault::read_file(&prev)? else {
        con.say("keygent: no vault.kgt.prev to restore — use 'keygent restore <backup>'");
        return Err(Error::Damaged);
    };
    let mut pv = Vault::open_bytes(d, bytes, Unlock::Passphrase(pass))?;
    if pv
        .index
        .handles
        .iter()
        .any(|r| pv.read_entry(&r.handle).is_err())
    {
        con.say("keygent: vault.kgt.prev is damaged too — use 'keygent restore <backup>'");
        return Err(Error::Damaged);
    }
    if !con.confirm("vault.kgt.prev verifies. Restore it (changes since then are lost)?")? {
        return Err(Error::Damaged);
    }
    pv.set_original(Vec::new());
    pv.commit(Prev::Drop)?;
    con.say("keygent: restored vault.kgt.prev");
    Ok(())
}

pub fn backup(a: Args) -> Result<()> {
    let [target] = a.pos.as_slice() else {
        return Err(Error::Usage("keygent backup <file>"));
    };
    let d = dirs()?;
    let _l = vault::lock(&d)?;
    let bytes = vault::read_file(&Vault::path(&d))?.ok_or(Error::NoVault)?;
    format::parse(&bytes)?;
    let target = PathBuf::from(target);
    let mut f = platform::os()
        .create_private(&target)
        .map_err(|e| match e {
            Error::Io(_) if target.exists() => {
                Error::Usage("backup target exists — pick a new file name")
            }
            e => e,
        })?;
    f.write_all(&bytes)?;
    platform::os().sync_file(&f)?;
    let _ = writeln!(
        std::io::stderr(),
        "keygent: backup written (encrypted; opens only with this device key or the recovery key)"
    );
    Ok(())
}

pub fn restore(a: Args) -> Result<()> {
    let [src] = a.pos.as_slice() else {
        return Err(Error::Usage("keygent restore <file> [--new-machine]"));
    };
    let d = dirs()?;
    seal_broker(&d)?;
    let l = vault::lock(&d)?;
    let src = PathBuf::from(src);
    let max = usize::try_from(format::MAX_FILE_LEN).unwrap_or(usize::MAX);
    let bytes = read_input_file(&src, max)?.expose().to_vec();
    format::parse(&bytes)?;
    let mut con = Console::open()?;
    if a.has("--new-machine") {
        return restore_new_machine(&mut con, &d, bytes, a.has("--own-passphrase"));
    }
    if a.has("--own-passphrase") {
        return Err(Error::Usage(
            "--own-passphrase only applies with --new-machine",
        ));
    }
    let live = vault::read_file(&Vault::path(&d))?;
    if let Some(live) = &live {
        let (lf, _) = format::parse(live)?;
        let (bf, _) = format::parse(&bytes)?;
        if lf.uuid != bf.uuid {
            return Err(Error::UuidMismatch);
        }
    }
    let pass = con.read_hidden("Passphrase (of the backup): ")?;
    let v = Vault::open_bytes(&d, bytes, Unlock::Passphrase(&pass))?;
    let mut v = confirm_rollback(&mut con, v)?;
    v.set_original(live.unwrap_or_default());
    v.commit(Prev::Keep)?;
    drop(l);
    con.say("keygent: restored (the replaced vault is kept as vault.kgt.prev)");
    Ok(())
}

/// SPEC §5.2: `restore --new-machine` uses the recovery key, sets a new passphrase with this device's key, clears
/// device-bound data (pinned executables, shell paths, passkeys, UI pin) and sets every handle to `approve`.
fn restore_new_machine(con: &mut Console, d: &Dirs, bytes: Vec<u8>, own: bool) -> Result<()> {
    if Vault::exists(d) {
        return Err(Error::VaultExists);
    }
    let rk = read_recovery_key(con)?;
    let mut v = Vault::open_bytes(d, bytes, Unlock::Recovery(&rk))?;
    let pass = new_passphrase(con, own)?;
    let pepper = v.keystore().pepper_or_create()?;
    v.set_passphrase(&pass, &pepper)?;
    for r in &mut v.index.handles {
        r.allow_rules.clear();
        r.mode = Mode::Approve;
        r.config_seen.clear();
    }
    v.index.shell_paths = index::ShellPaths::default();
    v.index.passkeys.clear();
    v.index.ui_binary_sha256 = None;
    v.keystore().clear_tripwire(&v.index.tripwire_id)?;
    v.set_original(Vec::new());
    v.commit(Prev::Drop)?;
    con.say("keygent: restored on this machine — every secret is set to 'approve'; pins and passkeys were cleared");
    Ok(())
}

// ---------------------------------------------------------------- secret commands

pub fn add(a: Args) -> Result<()> {
    let usage = "keygent add <handle> [--env NAME] [--description TEXT] [--multiline | --from-file PATH [--delete]]";
    let h = one_handle(&a, usage)?;
    let env = match a.value("--env") {
        Some(e) => e.to_owned(),
        None => names::default_env_name(&h),
    };
    names::check_env_name(&env)?;
    let desc = a.value("--description").unwrap_or_default().to_owned();
    check_description(&desc)?;
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    check_new_handle(&v.index, &h)?;
    let (value, src) = read_value(&mut con, &a)?;
    strength::check_secret(value.expose())?;
    let now = vault::now();
    v.index.handles.push(index::new_handle(
        &h,
        &env,
        &desc,
        v.index.security.default_mode,
        now,
    ));
    v.put_entry(&h, 1, &value)?;
    drop(value);
    audited_commit(&mut v, &d, Prev::Keep, "add", &[&h])?;
    con.say(&format!("keygent: added {h} (env {env})"));
    maybe_delete_source(&mut con, src, a.has("--delete"))
}

pub fn rotate(a: Args) -> Result<()> {
    let usage = "keygent rotate <handle> [--undo | --multiline | --from-file PATH [--delete]]";
    let h = one_handle(&a, usage)?;
    if a.has("--undo") && (a.has("--multiline") || a.has("--from-file")) {
        return Err(Error::Usage(usage));
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    let now = vault::now();
    v.index.expire_previous(now);
    let current = v.read_entry(&h)?;
    let (new, src) = if a.has("--undo") {
        let rec = v.index.get(&h).ok_or_else(|| Error::NotFound(h.clone()))?;
        let prev = rec
            .previous_value
            .as_ref()
            .ok_or_else(|| Error::NothingToUndo(h.clone()))?;
        (Secret::from_slice(prev.expose()), None)
    } else {
        let (n, src) = read_value(&mut con, &a)?;
        strength::check_secret(n.expose())?;
        if n.ct_eq(current.expose()) {
            return Err(Error::Usage("the new value equals the current one"));
        }
        check_redactor_cap(&v, &[n.expose()])?;
        (n, src)
    };
    let rec = v
        .index
        .get_mut(&h)
        .ok_or_else(|| Error::NotFound(h.clone()))?;
    let version = rec.version.checked_add(1).ok_or(Error::Damaged)?;
    rec.version = version;
    rec.rotated_at = now;
    rec.previous_value = Some(current);
    rec.previous_version_until = Some(now.saturating_add(index::PREVIOUS_KEEP_SECS));
    rec.exposed = false;
    v.put_entry(&h, version, &new)?;
    drop(new);
    audited_commit(&mut v, &d, Prev::Drop, "rotate", &[&h])?;
    con.say(&format!(
        "keygent: rotated {h} — the previous value can be restored with --undo for 24 h"
    ));
    maybe_delete_source(&mut con, src, a.has("--delete"))
}

pub fn rm(a: Args) -> Result<()> {
    let h = one_handle(&a, "keygent rm <handle>")?;
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    if v.index.get(&h).is_none() {
        return Err(Error::NotFound(h));
    }
    if !con.confirm(&format!("Remove {h}? This can't be undone"))? {
        return Err(Error::Cancelled);
    }
    v.index.handles.retain(|r| r.handle != h);
    v.remove_entry(&h);
    audited_commit(&mut v, &d, Prev::Drop, "rm", &[&h])?;
    con.say(&format!("keygent: removed {h}"));
    Ok(())
}

pub fn rename(a: Args) -> Result<()> {
    let [old, new] = a.pos.as_slice() else {
        return Err(Error::Usage("keygent rename <old> <new>"));
    };
    names::check_handle(old)?;
    names::check_handle(new)?;
    if old == new {
        return Err(Error::Usage("keygent rename <old> <new> (names differ)"));
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    if v.index.get(new).is_some() {
        return Err(Error::Exists(new.clone()));
    }
    if let Some(other) = names::collision(
        new,
        v.index
            .handles
            .iter()
            .map(|r| r.handle.as_str())
            .filter(|h| h != old),
    ) {
        return Err(Error::Collision(other.to_owned()));
    }
    let value = v.read_entry(old)?;
    let rec = v
        .index
        .get_mut(old)
        .ok_or_else(|| Error::NotFound(old.clone()))?;
    rec.handle = new.clone();
    let version = rec.version;
    v.remove_entry(old);
    v.put_entry(new, version, &value)?;
    drop(value);
    audited_commit(&mut v, &d, Prev::Keep, "rename", &[old, new])?;
    con.say(&format!("keygent: renamed {old} → {new}"));
    Ok(())
}

pub fn reveal(a: Args) -> Result<()> {
    let h = one_handle(&a, "keygent reveal <handle> [--copy]")?;
    if a.has("--copy") && platform::test_console() {
        // tests must never touch the developer's real clipboard
        return Err(Error::Unsupported("reveal --copy in test builds"));
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    // SPEC §5.5.1: reveal always needs a fresh passphrase proof
    let v = unlock(&mut con, &d, &l)?;
    let value = v.read_entry(&h)?;
    // every reveal is audited, and a reveal that can't be audited doesn't happen (SPEC §5.1)
    let mut r = audit::Record::new("reveal");
    r.handles = vec![h.clone()];
    r.channel = Some("terminal");
    audit::append(&d, &v.audit_key()?, &r)?;
    drop(v);
    drop(l);
    if !a.has("--copy") {
        return con.show_secret(
            &format!("{h} (clears after {REVEAL_SECS} s or a keypress)"),
            value.expose(),
            Duration::from_secs(REVEAL_SECS),
        );
    }
    // --copy: concealed clipboard, cleared after 10 s unless something else was copied meanwhile (SPEC §5.1)
    let text = std::str::from_utf8(value.expose())
        .map_err(|_| Error::Unsupported("reveal --copy of binary values"))?;
    let os = platform::os();
    let token = os.clipboard_put(text)?;
    con.say(&format!(
        "keygent: {h} copied — the clipboard clears in {COPY_SECS} s (keep this terminal open)"
    ));
    std::thread::sleep(Duration::from_secs(COPY_SECS));
    os.clipboard_clear_if_ours(token, text)?;
    con.say("keygent: clipboard cleared");
    Ok(())
}

fn parse_secs(a: &Args, f: &'static str, max: u32) -> Result<Option<u32>> {
    match a.value(f) {
        None => Ok(None),
        Some(s) => match s.parse::<u32>() {
            Ok(n) if n > 0 && n <= max => Ok(Some(n)),
            _ => Err(Error::Usage(f)),
        },
    }
}

pub fn edit(a: Args) -> Result<()> {
    if a.has("--settings") {
        return edit_settings(a);
    }
    let usage = "keygent edit <handle> [--env NAME] [--description TEXT] [--mode M] [--binding B] [--argv A]";
    let h = one_handle(&a, usage)?;
    let env = a.value("--env").map(str::to_owned);
    if let Some(e) = &env {
        names::check_env_name(e)?;
    }
    let desc = a.value("--description").map(str::to_owned);
    if let Some(dsc) = &desc {
        check_description(dsc)?;
    }
    let mode = a
        .value("--mode")
        .map(|m| Mode::parse(m).ok_or(Error::Usage("--mode allow|confirm|approve|deny")))
        .transpose()?;
    let binding = a
        .value("--binding")
        .map(|b| match b {
            "env" => Ok(Binding::Env),
            "file" => Ok(Binding::File),
            _ => Err(Error::Usage("--binding env|file")),
        })
        .transpose()?;
    let argv = a
        .value("--argv")
        .map(|b| match b {
            "deny" => Ok(Argv::Deny),
            "allow" => Ok(Argv::Allow),
            _ => Err(Error::Usage("--argv deny|allow")),
        })
        .transpose()?;
    if env.is_none() && desc.is_none() && mode.is_none() && binding.is_none() && argv.is_none() {
        return Err(Error::Usage(usage));
    }
    for f in [
        "--ttl-max",
        "--idle",
        "--run-max-minutes",
        "--remember",
        "--default-mode",
    ] {
        if a.has(f) {
            return Err(Error::Usage("settings flags need --settings"));
        }
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    let rec = v.index.get(&h).ok_or_else(|| Error::NotFound(h.clone()))?;
    let mut diff = Vec::new();
    if let Some(e) = &env {
        diff.push(format!("  env:         {} → {e}", rec.env_name));
    }
    if let Some(dsc) = &desc {
        diff.push(format!("  description: {:?} → {dsc:?}", rec.description));
    }
    if let Some(m) = mode {
        diff.push(format!("  mode:        {} → {}", rec.mode.name(), m.name()));
    }
    if let Some(b) = binding {
        diff.push(format!(
            "  binding:     {} → {}",
            rec.binding.name(),
            b.name()
        ));
    }
    if let Some(x) = argv {
        diff.push(format!("  argv:        {} → {}", rec.argv.name(), x.name()));
        if x == Argv::Allow {
            diff.push("  ⚠ argv allow: the value will be visible to other local users via the process list".into());
        }
    }
    con.say(&format!("Changes to {h}:"));
    for line in &diff {
        con.say(line);
    }
    if !con.confirm("Apply?")? {
        return Err(Error::Cancelled);
    }
    let policy_change = mode.is_some() || binding.is_some() || argv.is_some();
    let rec = v
        .index
        .get_mut(&h)
        .ok_or_else(|| Error::NotFound(h.clone()))?;
    if let Some(e) = env {
        rec.env_name = e;
    }
    if let Some(dsc) = desc {
        rec.description = dsc;
    }
    if let Some(m) = mode {
        rec.mode = m;
    }
    if let Some(b) = binding {
        rec.binding = b;
    }
    if let Some(x) = argv {
        rec.argv = x;
    }
    audited_commit(
        &mut v,
        &d,
        if policy_change {
            Prev::Drop
        } else {
            Prev::Keep
        },
        "edit",
        &[&h],
    )?;
    con.say(&format!("keygent: updated {h}"));
    Ok(())
}

fn edit_settings(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage(
            "keygent edit --settings [--ttl-max SECS] [--idle SECS] … (no handle)",
        ));
    }
    let ttl = parse_secs(&a, "--ttl-max", index::TTL_MAX_CEILING)?;
    let idle = parse_secs(&a, "--idle", index::TTL_MAX_CEILING)?;
    let run = parse_secs(&a, "--run-max-minutes", index::RUN_MAX_CEILING_MIN)?;
    let remember = a
        .value("--remember")
        .map(|r| match r {
            "on" => Ok(true),
            "off" => Ok(false),
            _ => Err(Error::Usage("--remember on|off")),
        })
        .transpose()?;
    let dm = a
        .value("--default-mode")
        .map(|m| Mode::parse(m).ok_or(Error::Usage("--default-mode MODE")))
        .transpose()?;
    if ttl.is_none() && idle.is_none() && run.is_none() && remember.is_none() && dm.is_none() {
        return Err(Error::Usage(
            "keygent edit --settings [--ttl-max SECS] [--idle SECS] [--run-max-minutes N] …",
        ));
    }
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    let s = v.index.security;
    con.say("Security settings:");
    if let Some(x) = ttl {
        con.say(&format!("  ttl-max:          {} s → {x} s", s.ttl_max_secs));
    }
    if let Some(x) = idle {
        con.say(&format!("  idle:             {} s → {x} s", s.idle_secs));
    }
    if let Some(x) = run {
        con.say(&format!("  run-max-minutes:  {} → {x}", s.run_max_minutes));
    }
    if let Some(x) = remember {
        con.say(&format!("  remember:         {} → {x}", s.remember_enabled));
    }
    if let Some(x) = dm {
        con.say(&format!(
            "  default-mode:     {} → {}",
            s.default_mode.name(),
            x.name()
        ));
    }
    if !con.confirm("Apply?")? {
        return Err(Error::Cancelled);
    }
    let sec = &mut v.index.security;
    sec.ttl_max_secs = ttl.unwrap_or(sec.ttl_max_secs);
    sec.idle_secs = idle.unwrap_or(sec.idle_secs);
    sec.run_max_minutes = run.unwrap_or(sec.run_max_minutes);
    sec.remember_enabled = remember.unwrap_or(sec.remember_enabled);
    sec.default_mode = dm.unwrap_or(sec.default_mode);
    audited_commit(&mut v, &d, Prev::Drop, "edit", &[])?;
    con.say("keygent: settings updated");
    Ok(())
}

pub fn import(a: Args) -> Result<()> {
    let [file] = a.pos.as_slice() else {
        return Err(Error::Usage(
            "keygent import <.env file> [--overwrite] [--delete]",
        ));
    };
    let path = PathBuf::from(file);
    let raw = read_input_file(&path, dotenv::MAX_FILE).map_err(|e| match e {
        Error::ValueSize => Error::TooLarge("1 MiB .env"),
        e => e,
    })?;
    let items = match dotenv::parse(raw.expose()) {
        Ok(i) => i,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "keygent: .env parse error on line {} — nothing imported",
                e.line
            );
            return Err(Error::Cancelled);
        }
    };
    drop(raw);
    let d = dirs()?;
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let mut v = unlock(&mut con, &d, &l)?;
    // plan: validate everything first, then apply in one write
    enum Act {
        Add,
        Overwrite,
    }
    let mut plan: Vec<(String, String, Secret, Act)> = Vec::new();
    let mut skipped = 0usize;
    for it in items {
        let Some(h) = names::handle_from_env_key(&it.key) else {
            con.say(&format!("  skip  {:<32} (can't form a handle)", it.key));
            skipped = skipped.saturating_add(1);
            continue;
        };
        if let Err(e) = names::check_env_name(&it.key) {
            con.say(&format!(
                "  skip  {:<32} ({})",
                it.key,
                e.to_string().trim_start_matches("keygent: ")
            ));
            skipped = skipped.saturating_add(1);
            continue;
        }
        if strength::check_secret(it.value.expose()).is_err() {
            con.say(&format!(
                "  skip  {:<32} (value too short or too weak)",
                it.key
            ));
            skipped = skipped.saturating_add(1);
            continue;
        }
        let exists = v.index.get(&h).is_some() || plan.iter().any(|(p, ..)| *p == h);
        if exists && !a.has("--overwrite") {
            con.say(&format!(
                "  skip  {:<32} ({h} exists; use --overwrite)",
                it.key
            ));
            skipped = skipped.saturating_add(1);
            continue;
        }
        if !exists {
            let others = v
                .index
                .handles
                .iter()
                .map(|r| r.handle.as_str())
                .chain(plan.iter().map(|(p, ..)| p.as_str()));
            if let Some(o) = names::collision(&h, others) {
                con.say(&format!("  skip  {:<32} (name clashes with {o})", it.key));
                skipped = skipped.saturating_add(1);
                continue;
            }
        }
        con.say(&format!(
            "  {}  {:<32} → {h}",
            if exists { "over" } else { "add " },
            it.key
        ));
        plan.push((
            h,
            it.key,
            it.value,
            if exists { Act::Overwrite } else { Act::Add },
        ));
    }
    if plan.is_empty() {
        con.say(&format!("keygent: nothing to import ({skipped} skipped)"));
        return Ok(());
    }
    if v.index
        .handles
        .len()
        .saturating_add(plan.iter().filter(|p| matches!(p.3, Act::Add)).count())
        > names::MAX_HANDLES
    {
        return Err(Error::TooLarge("1000 secrets"));
    }
    check_redactor_cap(&v, &plan.iter().map(|p| p.2.expose()).collect::<Vec<_>>())?;
    if !con.confirm(&format!("Import {} secret(s)?", plan.len()))? {
        return Err(Error::Cancelled);
    }
    let now = vault::now();
    let mut overwrote = false;
    for (h, key, value, act) in plan {
        match act {
            Act::Add => {
                v.index.handles.push(index::new_handle(
                    &h,
                    &key,
                    "",
                    v.index.security.default_mode,
                    now,
                ));
                v.put_entry(&h, 1, &value)?;
            }
            Act::Overwrite => {
                let cur = v.read_entry(&h)?;
                let rec = v
                    .index
                    .get_mut(&h)
                    .ok_or_else(|| Error::NotFound(h.clone()))?;
                let version = rec.version.checked_add(1).ok_or(Error::Damaged)?;
                rec.version = version;
                rec.rotated_at = now;
                rec.previous_value = Some(cur);
                rec.previous_version_until = Some(now.saturating_add(index::PREVIOUS_KEEP_SECS));
                v.put_entry(&h, version, &value)?;
                overwrote = true;
            }
        }
    }
    audited_commit(
        &mut v,
        &d,
        if overwrote { Prev::Drop } else { Prev::Keep },
        "add",
        &[],
    )?;
    con.say(&format!("keygent: imported ({skipped} skipped)"));
    maybe_delete_source(&mut con, Some(path), a.has("--delete"))
}
