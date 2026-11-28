//! `rule add|ls|rm` (SPEC §6.2): pinned allow rules, changed only with the passphrase (auth is the gate).
//!
//! `keygent rule add <handle> [--home scratch] -- <program> [args…] [** --flag --value-flag= …]`
//! - The program is resolved and pinned (absolute path + SHA-256) now; it is never executed to describe it.
//! - `*` = one argument that doesn't start with `-`; a trailing `**` is followed by the flag allowlist:
//!   `--name` (no value) or `--name=` (takes exactly one value).

use super::Args;
use super::cmds::{audited_commit, unlock};
use super::console::Console;
use crate::crypto::hex;
use crate::error::{Error, Result};
use crate::platform;
use crate::policy::allow::{self, FlagSpec};
use crate::policy::resolve;
use crate::vault::index::{AllowRule, Flag, Home, Mode};
use crate::vault::{self, Prev, names};
use std::path::{Path, PathBuf};

const USAGE: &str =
    "keygent rule add <handle> [--home scratch] -- <program> [args…] [** --flag --value-flag=]";

/// Resolve the program the human named, on their own PATH (they see the result before confirming).
fn resolve_exe(name: &str) -> Result<PathBuf> {
    let p = if name.contains('/') {
        PathBuf::from(name)
    } else {
        let path = std::env::var("PATH").unwrap_or_default();
        path.split(':')
            .filter(|d| Path::new(d).is_absolute())
            .map(|d| Path::new(d).join(name))
            .find(|p| p.is_file())
            .ok_or(Error::NotFound(name.to_owned()))?
    };
    std::fs::canonicalize(&p).map_err(|_| Error::NotFound(name.to_owned()))
}

fn describe(r: &AllowRule) -> String {
    let flags: Vec<String> = r
        .flags
        .iter()
        .map(|f| {
            if f.takes_value {
                format!("{} <value>", f.name)
            } else {
                f.name.clone()
            }
        })
        .collect();
    format!(
        "{} {}  [sha256 {}…{}{}]",
        r.exe,
        r.args.join(" "),
        hex(r.sha256.get(..4).unwrap_or_default()),
        if flags.is_empty() {
            String::new()
        } else {
            format!(", flags {}", flags.join(" "))
        },
        if r.home == Home::Scratch {
            ", home scratch"
        } else {
            ""
        }
    )
}

/// Split `args… ** --a --b=` into the pattern (ending in `**`) and the flag allowlist.
fn split_flags(words: &[String]) -> Result<(Vec<String>, Vec<FlagSpec>)> {
    let Some(pos) = words.iter().position(|w| w == "**") else {
        return Ok((words.to_vec(), Vec::new()));
    };
    let (pat, rest) = words.split_at(pos.saturating_add(1));
    let mut flags = Vec::new();
    for f in rest {
        let (name, takes_value) = match f.strip_suffix('=') {
            Some(n) => (n.to_owned(), true),
            None => (f.clone(), false),
        };
        flags.push(FlagSpec { name, takes_value });
    }
    Ok((pat.to_vec(), flags))
}

pub fn rule(a: Args) -> Result<()> {
    match a.pos.first().map(String::as_str) {
        Some("add") => add(&a),
        Some("ls") => ls(&a),
        Some("rm") => rm(&a),
        _ => Err(Error::Usage("keygent rule add|ls|rm — see 'keygent help'")),
    }
}

fn add(a: &Args) -> Result<()> {
    let [_, handle, exe_name, words @ ..] = a.pos.as_slice() else {
        return Err(Error::Usage(USAGE));
    };
    names::check_handle(handle)?;
    let home = match a.value("--home") {
        None | Some("inherit") => Home::Inherit,
        Some("scratch") => Home::Scratch,
        Some(_) => return Err(Error::Usage("--home inherit|scratch")),
    };
    let exe = resolve_exe(exe_name)?;
    let exe_s = exe
        .to_str()
        .ok_or(Error::Usage("program path must be UTF-8"))?
        .to_owned();
    let sha256 = resolve::hash_file(&exe).ok_or(Error::NotRegularFile)?;
    let (args, flags) = split_flags(words)?;
    allow::check_shape(&exe_s, &args, &flags).map_err(Error::Usage)?;
    let rule = AllowRule {
        exe: exe_s,
        sha256,
        args,
        flags: flags
            .into_iter()
            .map(|f| Flag {
                name: f.name,
                takes_value: f.takes_value,
            })
            .collect(),
        home,
    };
    let d = platform::dirs()?;
    let mut con = Console::open()?;
    con.say(&format!("allow rule for {handle}: {}", describe(&rule)));
    con.say("⚠ a pinned tool still reads config files you (or an agent) can edit — endpoints, proxies, credential");
    con.say("  helpers. Keep tools with such settings in 'approve', or use --home scratch.");
    let l = vault::lock(&d)?;
    let mut v = unlock(&mut con, &d, &l)?;
    let rec = v
        .index
        .get_mut(handle)
        .ok_or(Error::NotFound(handle.clone()))?;
    let mode = rec.mode;
    if rec.allow_rules.iter().any(|r| r == &rule) {
        con.say("keygent: that rule already exists — nothing changed");
        return Ok(());
    }
    rec.allow_rules.push(rule);
    audited_commit(&mut v, &d, Prev::Drop, "edit", &[handle])?;
    con.say(&format!("keygent: rule added for {handle}"));
    if mode != Mode::Allow {
        con.say(&format!(
            "keygent: {handle} is in '{}' mode — rules apply only in 'allow' ('keygent edit {handle} --mode allow')",
            mode.name()
        ));
    }
    Ok(())
}

fn ls(a: &Args) -> Result<()> {
    let [_, handle] = a.pos.as_slice() else {
        return Err(Error::Usage("keygent rule ls <handle>"));
    };
    let d = platform::dirs()?;
    let mut con = Console::open()?;
    let l = vault::lock(&d)?;
    let v = unlock(&mut con, &d, &l)?;
    let rec = v.index.get(handle).ok_or(Error::NotFound(handle.clone()))?;
    if rec.allow_rules.is_empty() {
        con.say(&format!("{handle}: no rules"));
    }
    for (i, r) in rec.allow_rules.iter().enumerate() {
        con.say(&format!("{}. {}", i.saturating_add(1), describe(r)));
    }
    Ok(())
}

fn rm(a: &Args) -> Result<()> {
    let [_, handle, n] = a.pos.as_slice() else {
        return Err(Error::Usage("keygent rule rm <handle> <n from 'rule ls'>"));
    };
    let n: usize = n
        .parse()
        .map_err(|_| Error::Usage("keygent rule rm <handle> <n>"))?;
    let d = platform::dirs()?;
    let mut con = Console::open()?;
    let l = vault::lock(&d)?;
    let mut v = unlock(&mut con, &d, &l)?;
    let rec = v
        .index
        .get_mut(handle)
        .ok_or(Error::NotFound(handle.clone()))?;
    let i = n
        .checked_sub(1)
        .filter(|i| *i < rec.allow_rules.len())
        .ok_or(Error::Usage("no such rule"))?;
    rec.allow_rules.remove(i);
    audited_commit(&mut v, &d, Prev::Drop, "edit", &[handle])?;
    con.say(&format!("keygent: rule {n} removed from {handle}"));
    Ok(())
}
