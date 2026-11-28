//! `keygent integrate claude [--remove]` (SPEC §5.10, ADR 0001): add or remove keygent's `PreToolUse` hook in Claude
//! Code's user settings (`~/.claude/settings.json`, home from the user database, never `$HOME`).
//!
//! The entry runs for every Bash command in exec form (no shell); `keygent hook pre` exits silently unless the command
//! holds a placeholder. No `if` filter: Claude Code strips leading env assignments before matching, so
//! `Bash(*{{keygent*)` misses `T={{keygent:h}} cmd` (verified on 2.1.332). `onFailure: continue`: if keygent is broken,
//! the command runs with the literal placeholder text, which holds no value, so failing open leaks nothing and never
//! blocks the user's other Bash commands. The file is merged, not replaced: key order is kept, a one-time backup is
//! written, and the write is atomic.
//!
//! **keygent goes first** (ADR 0002). Claude Code runs matching hooks in parallel and applies one `updatedInput`, so a
//! co-installed rewriter (lean-ctx) can replace keygent's rewrite with its own wrap of the original command (observed on
//! 2.1.332). Every group whose matcher names only Bash is therefore moved into keygent's entry as `--chain` args, run by
//! `keygent hook pre` after keygent's own step, and put back at its original index by `--remove`.

use super::Args;
use crate::error::{Error, Result};
use crate::hook::json::{self, Value};
use crate::platform::{self, Platform};
use std::io::Write;
use std::path::{Path, PathBuf};

fn home() -> Result<PathBuf> {
    #[cfg(feature = "test-profile")]
    if let Some(r) = std::env::var_os("KEYGENT_TEST_ROOT") {
        return Ok(PathBuf::from(r));
    }
    platform::os().home_dir()
}

/// The path hooks call: stable across upgrades (Homebrew's versioned Cellar path changes; `bin/keygent` doesn't).
fn launcher() -> Result<String> {
    let exe = std::env::current_exe()?;
    let s = exe.to_str().ok_or(Error::Internal(162))?;
    if let Some(i) = s.find("/Cellar/keygent/") {
        let bin = format!("{}/bin/keygent", s.get(..i).unwrap_or_default());
        if Path::new(&bin).exists() {
            return Ok(bin);
        }
    }
    Ok(s.to_owned())
}

fn is_ours(h: &Value) -> bool {
    matches!(h.get("args"), Some(Value::Arr(a)) if a.get(..2) == Some(&[Value::str("hook"), Value::str("pre")][..]))
        && h.get("command")
            .and_then(Value::as_str)
            .is_some_and(|c| Path::new(c).file_name().is_some_and(|n| n == "keygent"))
}

/// A group keygent runs behind itself (ADR 0002): its matcher names only Bash, and every hook is a plain command hook
/// (no `if` rule, which only Claude Code can evaluate, and not `async`).
fn chainable(g: &Value) -> bool {
    let bash_only = g.get("matcher").and_then(Value::as_str).is_some_and(|m| {
        m.split('|')
            .all(|alt| alt.trim().eq_ignore_ascii_case("bash"))
    });
    bash_only
        && matches!(g.get("hooks"), Some(Value::Arr(hs)) if !hs.is_empty() && hs.iter().all(|h| {
            h.get("type").and_then(Value::as_str) == Some("command")
                && h.get("command").and_then(Value::as_str).is_some()
                && h.get("if").is_none()
                && h.get("async").is_none_or(|a| *a == Value::Bool(false))
                && !is_ours(h)
        }))
}

/// Chained groups recorded in keygent's own hook args: `--chain {"at":<index>,"group":<original group>}`.
fn chained(h: &Value) -> Vec<(usize, Value)> {
    let Some(Value::Arr(a)) = h.get("args") else {
        return Vec::new();
    };
    a.windows(2)
        .filter(|w| w.first() == Some(&Value::str("--chain")))
        .filter_map(|w| json::parse(w.get(1)?.as_str()?.as_bytes()))
        .filter_map(|c| {
            let at = match c.get("at")? {
                Value::Num(n) => n.parse().ok()?,
                _ => return None,
            };
            Some((at, c.get("group")?.clone()))
        })
        .collect()
}

fn entry(launcher: &str, chain: &[(usize, Value)]) -> Value {
    let mut args = vec![Value::str("hook"), Value::str("pre")];
    // keygent's own step, then each chained hook's timeout (Claude Code's default for a command hook is 60 s)
    let mut timeout: u64 = 10;
    for (at, g) in chain {
        if let Some(Value::Arr(hs)) = g.get("hooks") {
            for h in hs {
                timeout = timeout.saturating_add(match h.get("timeout") {
                    Some(Value::Num(n)) => n.parse().unwrap_or(60),
                    _ => 60,
                });
            }
        }
        args.push(Value::str("--chain"));
        args.push(Value::Str(
            Value::Obj(vec![
                ("at".into(), Value::Num(at.to_string())),
                ("group".into(), g.clone()),
            ])
            .compact(),
        ));
    }
    Value::Obj(vec![
        ("matcher".into(), Value::str("Bash")),
        (
            "hooks".into(),
            Value::Arr(vec![Value::Obj(vec![
                ("type".into(), Value::str("command")),
                ("command".into(), Value::str(launcher)),
                ("args".into(), Value::Arr(args)),
                ("timeout".into(), Value::Num(timeout.min(600).to_string())),
                ("onFailure".into(), Value::str("continue")),
            ])]),
        ),
    ])
}

/// Settings with keygent's entry removed and the groups it chained put back where they were; unless `remove`, every
/// chainable Bash group is then moved behind a single keygent entry, added last. Returns the settings and how many
/// other `PreToolUse` groups still match Bash in parallel (their rewrites could win over keygent's).
fn merged(mut root: Value, launcher: &str, remove: bool) -> Result<(Value, usize)> {
    if !matches!(root, Value::Obj(_)) {
        return Err(Error::BadSettings);
    }
    if root.get("hooks").is_none() {
        root.set("hooks", Value::Obj(Vec::new()));
    }
    let hooks = root.get_mut("hooks").ok_or(Error::BadSettings)?;
    if !matches!(hooks, Value::Obj(_)) {
        return Err(Error::BadSettings);
    }
    let groups = match hooks.get("PreToolUse") {
        Some(Value::Arr(a)) => a.clone(),
        Some(_) => return Err(Error::BadSettings),
        None => Vec::new(),
    };
    let mut restore: Vec<(usize, Value)> = Vec::new();
    let mut groups: Vec<Value> = groups
        .into_iter()
        .filter_map(|mut g| {
            if let Some(Value::Arr(hs)) = g.get_mut("hooks") {
                hs.retain(|h| {
                    if is_ours(h) {
                        restore.extend(chained(h));
                        false
                    } else {
                        true
                    }
                });
                if hs.is_empty() {
                    return None;
                }
            }
            Some(g)
        })
        .collect();
    restore.sort_by_key(|(at, _)| *at);
    for (at, g) in restore {
        groups.insert(at.min(groups.len()), g);
    }
    let mut parallel: usize = 0;
    if !remove {
        let mut chain = Vec::new();
        let mut kept = Vec::new();
        for (i, g) in groups.into_iter().enumerate() {
            if chainable(&g) {
                chain.push((i, g));
            } else {
                if g.get("matcher").and_then(Value::as_str).is_none_or(|m| {
                    m.is_empty()
                        || m == "*"
                        || m.split('|')
                            .any(|a| a.to_ascii_lowercase().contains("bash"))
                        || m.contains(['.', '^', '$', '[', '(', '\\'])
                }) {
                    parallel = parallel.saturating_add(1);
                }
                kept.push(g);
            }
        }
        groups = kept;
        groups.push(entry(launcher, &chain));
    }
    if let Value::Obj(m) = hooks {
        if groups.is_empty() {
            m.retain(|(k, _)| k != "PreToolUse");
        } else {
            hooks.set("PreToolUse", Value::Arr(groups));
        }
    }
    // an empty `hooks` object is dropped (same meaning to Claude Code), so `--remove` restores the original file
    if matches!(root.get("hooks"), Some(Value::Obj(m)) if m.is_empty())
        && let Value::Obj(m) = &mut root
    {
        m.retain(|(k, _)| k != "hooks");
    }
    Ok((root, parallel))
}

pub fn claude(a: Args) -> Result<()> {
    if a.pos.as_slice() != ["claude"] {
        return Err(Error::Usage("keygent integrate claude [--remove]"));
    }
    let remove = a.has("--remove");
    let dir = home()?.join(".claude");
    let path = dir.join("settings.json");
    let existing = match std::fs::read(&path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let root = match &existing {
        Some(b) => json::parse(b).ok_or(Error::BadSettings)?,
        None => Value::Obj(Vec::new()),
    };
    let (out, parallel) = merged(root, &launcher()?, remove)?;
    let out = out.pretty();
    std::fs::create_dir_all(&dir)?;
    let mode = std::fs::metadata(&path).map_or(0o600, |m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o777
    });
    let backup = dir.join("settings.json.keygent-backup");
    if let Some(b) = &existing
        && !backup.exists()
    {
        write_atomic(&backup, b, mode)?;
    }
    write_atomic(&path, out.as_bytes(), mode)?;
    let _ = writeln!(
        std::io::stderr(),
        "{}",
        if remove {
            "keygent: Claude Code hook removed from ~/.claude/settings.json"
        } else {
            "keygent: Claude Code hook installed in ~/.claude/settings.json (backup: settings.json.keygent-backup)"
        }
    );
    if parallel > 0 {
        let _ = writeln!(
            std::io::stderr(),
            "keygent: {parallel} other PreToolUse hook(s) may also match Bash — check they don't rewrite commands"
        );
    }
    Ok(())
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let tmp = path.with_extension("keygent-tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    const K: &str = "/usr/local/bin/keygent";

    #[test]
    fn merge_keeps_user_settings_and_is_idempotent() {
        let user = json::parse(
            br#"{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"fmt"}]}],"PostToolUse":[]},"permissions":{"deny":["Read(./.env)"]}}"#,
        )
        .unwrap();
        let (once, parallel) = merged(user.clone(), K, false).unwrap();
        assert_eq!(parallel, 0);
        let (twice, _) = merged(once.clone(), K, false).unwrap();
        assert_eq!(once, twice, "installing twice adds one entry");
        let s = once.compact();
        assert!(s.starts_with(r#"{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"type":"command","command":"fmt"}]},"#), "{s}");
        assert!(
            s.contains(r#""command":"/usr/local/bin/keygent","args":["hook","pre"],"timeout":10,"onFailure":"continue""#)
                && !s.contains(r#""if":"#),
            "{s}"
        );
        assert!(
            s.ends_with(r#""permissions":{"deny":["Read(./.env)"]}}"#),
            "{s}"
        );
        assert_eq!(
            merged(once, K, true).unwrap().0,
            user,
            "remove restores the original exactly"
        );
    }

    #[test]
    fn bash_only_groups_are_chained_behind_keygent_and_restored_in_place() {
        let user = json::parse(
            br#"{"hooks":{"PreToolUse":[
              {"matcher":"Read","hooks":[{"type":"command","command":"r"}]},
              {"matcher":"Bash|bash","hooks":[{"type":"command","command":"/opt/homebrew/bin/lean-ctx hook rewrite"}]},
              {"matcher":"Bash","hooks":[{"type":"command","command":"x","if":"Bash(git *)"}]},
              {"matcher":".*","hooks":[{"type":"command","command":"audit","timeout":5}]}]}}"#,
        )
        .unwrap();
        let (once, parallel) = merged(user.clone(), K, false).unwrap();
        assert_eq!(
            parallel, 2,
            "the `if` group and the `.*` group stay parallel"
        );
        let pre = once.get("hooks").unwrap().get("PreToolUse").unwrap();
        let Value::Arr(gs) = pre else { panic!() };
        assert_eq!(gs.len(), 4);
        let ours = gs[3].get("hooks").unwrap();
        let Value::Arr(hs) = ours else { panic!() };
        let s = hs[0].compact();
        assert!(
            s.contains(
                r#""args":["hook","pre","--chain","{\"at\":1,\"group\":{\"matcher\":\"Bash|bash\""#
            ) && s.contains(r#""timeout":70"#),
            "{s}"
        );
        let (twice, _) = merged(once.clone(), K, false).unwrap();
        assert_eq!(
            once, twice,
            "re-install recovers the chain, then chains it again"
        );
        assert_eq!(
            merged(once, K, true).unwrap().0,
            user,
            "remove puts lean-ctx back at index 1"
        );
    }

    #[test]
    fn refuses_shapes_it_does_not_understand() {
        for bad in [
            &br#"[]"#[..],
            br#"{"hooks":[]}"#,
            br#"{"hooks":{"PreToolUse":{}}}"#,
        ] {
            let v = json::parse(bad).unwrap();
            assert_eq!(merged(v, "/k/keygent", false), Err(Error::BadSettings));
        }
    }
}
