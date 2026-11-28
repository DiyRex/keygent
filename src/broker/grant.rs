//! Grants (SPEC §5.5.2): a pending authorization to run one exact command.
//!
//! - The grant stores the command; `run --grant <id>` carries no command text.
//! - Grant key = SHA-256 over `enc()` of: command, dialect, cwd, handles, every resolved program (path + SHA-256),
//!   script files (path + SHA-256 + size), max runtime. Single-use: consumed by the first `Run`.
//! - Approval happens only through broker-observed channels (here: `keygent approve` with a passphrase proof).
//! - Limits (SPEC §4.1): 16 pending, 4 per cwd (oldest from the same cwd evicted), dedupe by key, 5 min queue life.
//! - Phase 2 ships no per-tool grammars, so every approved run is **unbound** (warning shown, `--remember` off). That
//!   is the conservative reading of "anything not proven bound is unbound" (BUILD_PROMPT §3.5).

use super::clock::Deadline;
use crate::crypto;
use crate::error::{Error, Result};
use crate::policy::allow::{self, FlagSpec};
use crate::policy::render::{self, ProgramLine, RenderInput, ScriptView};
use crate::policy::resolve::{self, Program};
use crate::policy::rewrite::{self, Binding, RewriteError};
use crate::policy::tokenize::{self, TokError};
use crate::vault::index::{AllowRule, Argv, Binding as IxBinding, Home, Index, Mode};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What `build` needs to know about each handle, snapshotted under the state lock (no values).
pub struct HandlePolicy {
    pub handle: String,
    pub env_name: String,
    pub mode: Mode,
    pub argv: Argv,
    pub file: bool,
    pub rules: Vec<AllowRule>,
    /// Env-bound handle with credential custody on (ADR 0022): the child only ever gets a dummy.
    pub custody: bool,
}

pub fn policy_snapshot(index: &Index) -> Vec<HandlePolicy> {
    index
        .handles
        .iter()
        .map(|r| HandlePolicy {
            handle: r.handle.clone(),
            env_name: r.env_name.clone(),
            mode: r.mode,
            argv: r.argv,
            file: r.binding == IxBinding::File,
            rules: r.allow_rules.clone(),
            custody: r.custody && r.binding == IxBinding::Env,
        })
        .collect()
}

fn lookup<'a>(snap: &'a [HandlePolicy], h: &str) -> Option<&'a HandlePolicy> {
    snap.iter().find(|x| x.handle == h)
}

pub const MAX_PENDING: usize = 16;
pub const MAX_PER_CWD: usize = 4;
pub const MAX_GRANTS: usize = 64;
pub const QUEUE_LIFE: Duration = Duration::from_secs(5 * 60);
pub const MAX_SCRIPT: u64 = 16 * 1024;
pub const DEFAULT_RUNTIME: Duration = Duration::from_secs(30 * 60);
pub const MAX_RUNTIME: Duration = Duration::from_secs(4 * 3600);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Pending,
    Approved,
    Denied,
    Consumed,
}

pub struct Script {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub content: Vec<u8>,
    /// The script word is rewritten to `"${KEYGENT_SCRIPT_<n>}"`, set at run time to the private copy.
    pub var: String,
}

pub struct Grant {
    /// Allow-rule path (§5.7): exec the pinned program (`programs[0]`) with this argv, without a shell.
    pub direct: Option<Vec<String>>,
    /// Run with an empty temp HOME and XDG dirs (rule `home = "scratch"`).
    pub scratch: bool,
    /// `capture`: stdout is stored as this new handle, never returned.
    pub capture: Option<String>,
    pub id: [u8; 16],
    pub key: [u8; 32],
    /// The command as requested (placeholders, never values): shown, hashed and audited.
    pub command: String,
    pub rewritten: String,
    pub cwd: PathBuf,
    pub handles: Vec<String>,
    pub bindings: Vec<Binding>,
    pub programs: Vec<Program>,
    pub scripts: Vec<Script>,
    pub max_runtime: Duration,
    pub unbound: bool,
    pub created: Deadline,
    pub state: State,
    pub rendered: String,
}

/// What a client asked for.
pub struct Request<'a> {
    pub command: &'a str,
    pub cwd: &'a str,
    pub max_runtime: Option<Duration>,
    /// `capture <handle>`: the new handle stdout will be stored as (part of the grant key, shown in the approval).
    pub capture: Option<&'a str>,
}

/// Whole minutes, rounded up (display and the limit message).
pub fn minutes(d: Duration) -> u64 {
    d.as_secs().div_ceil(60)
}

/// Folders a run may never start in (SPEC §5.5.2 "cwd rule").
fn forbidden_cwd(cwd: &Path, home: Option<&Path>) -> bool {
    let sys = [
        "/",
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/var",
        "/tmp",
        "/private",
        "/System",
        "/Library",
        "/Applications",
        "/opt",
        "/dev",
        "/proc",
        "/sys",
    ];
    sys.iter().any(|s| cwd == Path::new(s)) || home.is_some_and(|h| cwd == h)
}

/// Nearest ancestor with `.git` or `.keygent.toml` (UX only for direct runs: an agent can create one anywhere).
pub fn project_root(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .find(|d| d.join(".git").exists() || d.join(".keygent.toml").exists())
        .map(Path::to_path_buf)
}

fn tok_err(e: &TokError) -> Error {
    match e {
        TokError::TooLong => Error::TooLarge("64 KiB command"),
        _ => Error::Policy(crate::error::PolicyMsg::Unparsable),
    }
}

/// Read a script once (regular file, inside `root`, ≤ 16 KiB): the exact bytes that will run.
/// (canonical path, SHA-256, content) of a bindable script.
type ScriptBytes = (PathBuf, [u8; 32], Vec<u8>);

fn read_script(path: &Path, root: &Path) -> Result<Option<ScriptBytes>> {
    let Ok(canon) = std::fs::canonicalize(path) else {
        return Ok(None);
    };
    let Ok(m) = std::fs::metadata(&canon) else {
        return Ok(None);
    };
    if !m.is_file() {
        return Ok(None);
    }
    if !canon.starts_with(root) || m.len() > MAX_SCRIPT {
        return Err(Error::Policy(crate::error::PolicyMsg::ScriptNotBindable));
    }
    let content = std::fs::read(&canon)?;
    if u64::try_from(content.len()).unwrap_or(u64::MAX) > MAX_SCRIPT {
        return Err(Error::Policy(crate::error::PolicyMsg::ScriptNotBindable));
    }
    Ok(Some((canon, crypto::sha256(&content), content)))
}

fn has_shebang(p: &Path) -> bool {
    let mut b = [0u8; 2];
    std::fs::File::open(p)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b))
        .is_ok_and(|()| &b == b"#!")
}

/// Shebang interpreter of a script (`#!/bin/sh`, `#!/usr/bin/env node`), resolved on the captured PATH.
fn shebang(content: &[u8], cwd: &Path, path_var: &str) -> Option<PathBuf> {
    let line = content.strip_prefix(b"#!")?;
    let line = line.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim();
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    let target = if first.ends_with("/env") {
        parts.find(|p| !p.starts_with('-'))?
    } else {
        first
    };
    match resolve::resolve(Some(target), cwd, path_var) {
        Program::File { path, .. } => Some(path),
        _ => None,
    }
}

/// Record a bound script and the edit that replaces its word with `"${KEYGENT_SCRIPT_<n>}"`.
fn bind_script(
    scripts: &mut Vec<Script>,
    edits: &mut Vec<(usize, usize, String)>,
    span: Option<&(usize, usize)>,
    path: PathBuf,
    sha256: [u8; 32],
    content: Vec<u8>,
) -> Result<()> {
    let &(start, end) = span.ok_or(Error::Policy(crate::error::PolicyMsg::Unparsable))?;
    let var = format!("KEYGENT_SCRIPT_{}", scripts.len());
    edits.push((start, end, format!("\"${{{var}}}\"")));
    scripts.push(Script {
        path,
        sha256,
        content,
        var,
    });
    Ok(())
}

/// Build a grant (not yet stored). Errors are agent-facing policy decisions.
/// Placeholder handles of the command: each must exist and not be denied (first-seen order, no duplicates).
fn placeholder_handles(parsed: &tokenize::Parsed, snap: &[HandlePolicy]) -> Result<Vec<String>> {
    let mut handles: Vec<String> = Vec::new();
    for p in &parsed.placeholders {
        let mode = lookup(snap, &p.handle)
            .ok_or_else(|| Error::Policy(crate::error::PolicyMsg::UnknownHandle(p.handle.clone())))?
            .mode;
        if mode == Mode::Deny {
            return Err(Error::Policy(crate::error::PolicyMsg::NotAllowed(
                p.handle.clone(),
            )));
        }
        if !handles.contains(&p.handle) {
            handles.push(p.handle.clone());
        }
    }
    Ok(handles)
}

/// What `bind_programs` pins and binds.
struct Bound {
    programs: Vec<Program>,
    scripts: Vec<Script>,
    /// `(start, end, replacement)` edits replacing each bound script word with its private copy's env var.
    edits: Vec<(usize, usize, String)>,
}

/// Resolve and pin every command word (SPEC §5.5.2 "Executable binding") and bind every script it names
/// ("Script binding"): `source x`, interpreter + script, or a project-local shebang script.
fn bind_programs(
    parsed: &tokenize::Parsed,
    cwd: &Path,
    bind_root: &Path,
    path_var: &str,
) -> Result<Bound> {
    let mut programs = Vec::new();
    let mut scripts = Vec::new();
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for c in &parsed.commands {
        let Some(word0) = c.argv.first() else {
            continue;
        };
        let prog = resolve::resolve(word0.as_deref(), cwd, path_var);
        // `source x` / `. x`: the sourced file is a script run by the dialect shell
        if let Program::Builtin(b) = &prog
            && (b == "source" || b == ".")
            && let Some(Some(arg)) = c.argv.get(1)
        {
            let p = cwd.join(arg);
            if let Some((canon, sha256, content)) = read_script(&p, bind_root)? {
                bind_script(
                    &mut scripts,
                    &mut edits,
                    c.spans.get(1),
                    canon,
                    sha256,
                    content,
                )?;
            }
        }
        if let Program::File { path, .. } = &prog {
            if resolve::is_script_interpreter(path) {
                // first non-flag literal argument is the script (`python x.py`, `bash ./x.sh`)
                if let Some((i, Some(arg))) = c
                    .argv
                    .iter()
                    .enumerate()
                    .skip(1)
                    .find(|(_, a)| a.as_deref().is_none_or(|s| !s.starts_with('-')))
                {
                    let p = if Path::new(arg).is_absolute() {
                        PathBuf::from(arg)
                    } else {
                        cwd.join(arg)
                    };
                    if let Some((canon, sha256, content)) = read_script(&p, bind_root)? {
                        bind_script(
                            &mut scripts,
                            &mut edits,
                            c.spans.get(i),
                            canon,
                            sha256,
                            content,
                        )?;
                    }
                }
            } else if path.starts_with(bind_root) && has_shebang(path) {
                // a project-local script: bind its bytes (compiled binaries are pinned like any program)
                if let Some((canon, sha256, content)) = read_script(path, bind_root)?
                    && let Some(interp) = shebang(&content, cwd, path_var)
                {
                    // the private copy is exec'd directly; its shebang interpreter is pinned like any program
                    programs.push(resolve::resolve(interp.to_str(), cwd, path_var));
                    bind_script(
                        &mut scripts,
                        &mut edits,
                        c.spans.first(),
                        canon,
                        sha256,
                        content,
                    )?;
                    continue;
                }
            }
        }
        programs.push(prog);
    }
    Ok(Bound {
        programs,
        scripts,
        edits,
    })
}

/// One approval line per pinned program.
fn program_lines(programs: &[Program]) -> Vec<ProgramLine> {
    programs
        .iter()
        .map(|p| match p {
            Program::File { path, sha256 } => ProgramLine {
                path: path.display().to_string(),
                sha256: Some(*sha256),
            },
            Program::Builtin(b) => ProgramLine {
                path: format!("{b} (shell builtin)"),
                sha256: None,
            },
            Program::Unknown(w) => ProgramLine {
                path: w.clone(),
                sha256: None,
            },
        })
        .collect()
}

/// `snap` is the handles' policy, snapshotted under the state lock.
/// `trusted`: (canonical manifest path, SHA-256) pairs the human trusted.
pub fn build(
    req: &Request<'_>,
    snap: &[HandlePolicy],
    trusted: &[(String, [u8; 32])],
    path_var: &str,
    home: Option<&Path>,
) -> Result<Grant> {
    if let Some(h) = req.capture {
        crate::vault::names::check_handle(h)?;
        // create-only: overwriting is the human's `rotate` (SPEC §5.9); refuse before asking anyone to approve
        if lookup(snap, h).is_some() {
            return Err(Error::NeedsAuth);
        }
    }
    let parsed = tokenize::parse(req.command).map_err(|e| tok_err(&e))?;
    let mut handles = placeholder_handles(&parsed, snap)?;
    let argv_exposed = parsed
        .placeholders
        .iter()
        .any(|p| !p.file && p.role == tokenize::Role::Argv);
    let cwd = std::fs::canonicalize(req.cwd)
        .map_err(|_| Error::Policy(crate::error::PolicyMsg::BadCwd))?;
    if !cwd.is_dir() || forbidden_cwd(&cwd, home) {
        return Err(Error::Policy(crate::error::PolicyMsg::BadCwd));
    }
    let root = project_root(&cwd);
    let (manifest_bindings, manifest_note) = manifest_refs(&parsed, &cwd, snap, trusted)?;
    let bind_root = root.clone().unwrap_or_else(|| cwd.clone());
    let max_runtime = req.max_runtime.unwrap_or(DEFAULT_RUNTIME);
    if max_runtime.is_zero() || max_runtime > MAX_RUNTIME {
        return Err(Error::Usage("--max-runtime: 1s … 4h"));
    }
    if let Some(argv) = allow::eligible(&parsed)
        && let Some(g) = allow_grant(
            req,
            &argv,
            snap,
            &cwd,
            root.as_deref(),
            path_var,
            max_runtime,
        )?
    {
        return Ok(g);
    }
    let Bound {
        programs,
        scripts,
        edits,
    } = bind_programs(&parsed, &cwd, &bind_root, path_var)?;
    let rw = rewrite::rewrite(
        req.command,
        &parsed,
        |h| lookup(snap, h).is_some_and(|x| x.argv == Argv::Allow),
        &edits,
    )
    .map_err(|e| match e {
        RewriteError::ArgvSecret(_) => Error::Policy(crate::error::PolicyMsg::ArgvSecret),
        RewriteError::SingleQuoted(_) => Error::Policy(crate::error::PolicyMsg::SingleQuoted),
        RewriteError::Overlap => Error::Policy(crate::error::PolicyMsg::Unparsable),
    })?;
    let mut bindings = rw.bindings;
    for b in manifest_bindings {
        if !handles.contains(&b.handle) {
            handles.push(b.handle.clone());
        }
        bindings.push(b);
    }
    // custody handles reach the child only as dummies, so a command using nothing else needs no per-command approval
    // (ADR 0022); a capture always needs approval: it writes a new secret into the vault (ADR 0015 §5, review fix)
    let custody_only = !handles.is_empty()
        && handles
            .iter()
            .all(|h| lookup(snap, h).is_some_and(|x| x.custody));
    let needs_approval = req.capture.is_some()
        || ((!parsed.placeholders.is_empty() || !handles.is_empty()) && !custody_only);
    let key = grant_key(
        req.command,
        &cwd,
        &handles,
        &programs,
        &scripts,
        max_runtime,
        req.capture,
    )?;
    let mut notes = manifest_note;
    if custody_only {
        notes.push("custody: the command gets dummies; real values go only to approved hosts via $KEYGENT_PROXY_URL".into());
    }
    notes.extend(capture_note(req.capture));
    let env: Vec<(String, String)> = bindings
        .iter()
        .map(|b| (b.handle.clone(), b.var.clone()))
        .collect();
    let program_lines = program_lines(&programs);
    let script_views: Vec<ScriptView> = scripts
        .iter()
        .map(|s| ScriptView {
            path: s.path.display().to_string(),
            sha256: s.sha256,
            content: s.content.clone(),
        })
        .collect();
    let cwd_s = cwd.display().to_string();
    let root_s = root.as_ref().map(|r| r.display().to_string());
    let rendered = render::render_for_approval(&RenderInput {
        grant_key: &key,
        command: req.command,
        cwd: &cwd_s,
        project_root: root_s.as_deref(),
        env: &env,
        programs: &program_lines,
        scripts: &script_views,
        unbound: true,
        argv_exposed,
        max_runtime_min: minutes(max_runtime),
        notes: &notes,
    });
    Ok(Grant {
        direct: None,
        scratch: false,
        capture: req.capture.map(str::to_owned),
        id: crypto::random()?,
        key,
        command: req.command.to_owned(),
        rewritten: rw.cmd,
        cwd,
        handles,
        bindings,
        programs,
        scripts,
        max_runtime,
        unbound: true,
        created: Deadline::after(QUEUE_LIFE),
        state: if needs_approval {
            State::Pending
        } else {
            State::Approved
        },
        rendered,
    })
}

/// Env names from the project manifest that the command references (`$NAME`, SPEC §5.7 step 2). The manifest must be
/// trusted with exactly this content, every referenced handle must exist and not be denied, and the argv rule applies
/// to `$NAME` as to placeholders. Unreferenced manifest entries inject nothing.
fn manifest_refs(
    parsed: &tokenize::Parsed,
    cwd: &Path,
    snap: &[HandlePolicy],
    trusted: &[(String, [u8; 32])],
) -> Result<(Vec<Binding>, Vec<String>)> {
    if parsed.vars.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let Some(m) = crate::policy::manifest::find(cwd) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let path = m.path.display().to_string();
    let is_trusted = trusted
        .iter()
        .any(|(p, h)| *p == path && crypto::ct_eq(h, &m.sha256));
    let entries = m.entries.as_ref().ok();
    let mut out: Vec<Binding> = Vec::new();
    for v in &parsed.vars {
        let Some(e) = entries.and_then(|es| es.iter().find(|e| e.env == v.name)) else {
            // a changed or broken manifest can't vouch for any name; one we can't parse fails closed below
            if entries.is_none() && !is_trusted {
                return Err(Error::Policy(crate::error::PolicyMsg::NotTrusted));
            }
            continue;
        };
        if !is_trusted {
            return Err(Error::Policy(crate::error::PolicyMsg::NotTrusted));
        }
        let h = lookup(snap, &e.handle).ok_or_else(|| {
            Error::Policy(crate::error::PolicyMsg::UnknownHandle(e.handle.clone()))
        })?;
        if h.mode == Mode::Deny {
            return Err(Error::Policy(crate::error::PolicyMsg::NotAllowed(
                e.handle.clone(),
            )));
        }
        if !e.file
            && matches!(v.role, tokenize::Role::Argv | tokenize::Role::Redirect)
            && h.argv != Argv::Allow
        {
            return Err(Error::Policy(crate::error::PolicyMsg::ArgvSecret));
        }
        if !out.iter().any(|b| b.var == e.env) {
            out.push(Binding {
                var: e.env.clone(),
                handle: e.handle.clone(),
                file: e.file,
            });
        }
    }
    let note = if out.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "manifest: {path} (trusted, sha256 {})",
            crypto::hex8(&m.sha256)
        )]
    };
    Ok((out, note))
}

/// Allow-rule path (SPEC §5.7 step 4, §6.2): handles in `allow` mode whose rule matches the pinned program and argv.
/// A matching pin pre-approves the grant (bound, no shell); a changed binary falls back to approval with a re-pin
/// warning (the binary is never executed to describe it). `None` = no rule matched.
fn capture_note(capture: Option<&str>) -> Option<String> {
    capture.map(|h| {
        format!("⚠ capture: stdout (trimmed) is stored as the new secret {h} and not shown")
    })
}

fn allow_grant(
    req: &Request<'_>,
    argv: &[String],
    snap: &[HandlePolicy],
    cwd: &Path,
    root: Option<&Path>,
    path_var: &str,
    max_runtime: Duration,
) -> Result<Option<Grant>> {
    let Program::File { path, sha256 } =
        resolve::resolve(argv.first().map(String::as_str), cwd, path_var)
    else {
        return Ok(None);
    };
    let Some(exe) = path.to_str() else {
        return Ok(None);
    };
    let rest = argv.get(1..).unwrap_or_default();
    let mut bindings = Vec::new();
    let mut handles = Vec::new();
    let mut stale: Vec<[u8; 32]> = Vec::new();
    let mut scratch = false;
    for h in snap.iter().filter(|h| h.mode == Mode::Allow) {
        let hit = h.rules.iter().find(|r| {
            let flags: Vec<FlagSpec> = r
                .flags
                .iter()
                .map(|f| FlagSpec {
                    name: f.name.clone(),
                    takes_value: f.takes_value,
                })
                .collect();
            r.exe == exe && allow::matches(&r.args, &flags, rest)
        });
        if let Some(r) = hit {
            if !crypto::ct_eq(&r.sha256, &sha256) {
                stale.push(r.sha256);
            }
            scratch |= r.home == Home::Scratch;
            handles.push(h.handle.clone());
            bindings.push(Binding {
                var: h.env_name.clone(),
                handle: h.handle.clone(),
                file: h.file,
            });
        }
    }
    if handles.is_empty() {
        return Ok(None);
    }
    let programs = vec![Program::File {
        path: path.clone(),
        sha256,
    }];
    let command = req.command;
    let key = grant_key(
        command,
        cwd,
        &handles,
        &programs,
        &[],
        max_runtime,
        req.capture,
    )?;
    let mut notes = vec![format!(
        "allow rule matched — runs {exe} directly, without a shell"
    )];
    for old in &stale {
        let m = std::fs::metadata(&path).ok();
        notes.push(format!(
            "⚠ re-pin: {exe} changed since the rule was approved (sha256 {} → {}, {} B, mtime {})",
            crypto::hex8(old),
            crypto::hex8(&sha256),
            m.as_ref().map_or(0, std::fs::Metadata::len),
            m.and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs())
        ));
    }
    if scratch {
        notes.push("home: scratch (empty temp HOME and XDG dirs)".into());
    }
    notes.extend(capture_note(req.capture));
    let env: Vec<(String, String)> = bindings
        .iter()
        .map(|b| (b.handle.clone(), b.var.clone()))
        .collect();
    let cwd_s = cwd.display().to_string();
    let root_s = root.map(|r| r.display().to_string());
    let rendered = render::render_for_approval(&RenderInput {
        grant_key: &key,
        command,
        cwd: &cwd_s,
        project_root: root_s.as_deref(),
        env: &env,
        programs: &[ProgramLine {
            path: exe.to_owned(),
            sha256: Some(sha256),
        }],
        scripts: &[],
        unbound: false,
        argv_exposed: false,
        max_runtime_min: minutes(max_runtime),
        notes: &notes,
    });
    Ok(Some(Grant {
        direct: Some(argv.to_vec()),
        scratch,
        capture: req.capture.map(str::to_owned),
        id: crypto::random()?,
        key,
        command: command.to_owned(),
        rewritten: String::new(),
        cwd: cwd.to_path_buf(),
        handles,
        bindings,
        programs,
        scripts: Vec::new(),
        max_runtime,
        unbound: false,
        created: Deadline::after(QUEUE_LIFE),
        state: if stale.is_empty() && req.capture.is_none() {
            State::Approved
        } else {
            State::Pending
        },
        rendered,
    }))
}

pub fn grant_key(
    command: &str,
    cwd: &Path,
    handles: &[String],
    programs: &[Program],
    scripts: &[Script],
    max_runtime: Duration,
    capture: Option<&str>,
) -> Result<[u8; 32]> {
    let mut fields: Vec<Vec<u8>> = vec![
        command.as_bytes().to_vec(),
        b"posix".to_vec(),
        cwd.as_os_str().as_encoded_bytes().to_vec(),
    ];
    fields.push(handles.join("\0").into_bytes());
    for p in programs {
        match p {
            Program::File { path, sha256 } => {
                fields.push(path.as_os_str().as_encoded_bytes().to_vec());
                fields.push(sha256.to_vec());
            }
            Program::Builtin(b) => fields.push(format!("builtin:{b}").into_bytes()),
            Program::Unknown(w) => fields.push(format!("unknown:{w}").into_bytes()),
        }
    }
    for s in scripts {
        fields.push(s.path.as_os_str().as_encoded_bytes().to_vec());
        fields.push(s.sha256.to_vec());
        fields.push(
            u64::try_from(s.content.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes()
                .to_vec(),
        );
    }
    fields.push(max_runtime.as_secs().to_le_bytes().to_vec());
    fields.push(capture.map_or_else(Vec::new, |h| format!("capture:{h}").into_bytes()));
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    Ok(crypto::sha256(&crypto::enc(&refs)?))
}

/// Insert respecting the queue limits; returns the id to hand back (an existing grant with the same key is reused).
/// Every grant ages out at its deadline (5 min from creation, reset on approval); denied and consumed ones stay
/// until then so a waiting `run` learns the outcome. `MAX_GRANTS` bounds memory (oldest decided ones go first).
pub fn insert(grants: &mut Vec<Grant>, g: Grant) -> Result<[u8; 16]> {
    prune(grants);
    while grants.len() >= MAX_GRANTS {
        match grants.iter().position(|x| x.state != State::Pending) {
            Some(pos) => {
                grants.remove(pos);
            }
            None => return Err(Error::RateLimited),
        }
    }
    if let Some(x) = grants
        .iter()
        .find(|x| x.key == g.key && matches!(x.state, State::Pending | State::Approved))
    {
        return Ok(x.id);
    }
    let pending = |gs: &Vec<Grant>| gs.iter().filter(|x| x.state == State::Pending).count();
    if g.state == State::Pending {
        let same_cwd = grants
            .iter()
            .filter(|x| x.state == State::Pending && x.cwd == g.cwd)
            .count();
        if same_cwd >= MAX_PER_CWD
            && let Some(pos) = grants
                .iter()
                .position(|x| x.state == State::Pending && x.cwd == g.cwd)
        {
            grants.remove(pos);
        }
        if pending(grants) >= MAX_PENDING {
            return Err(Error::RateLimited);
        }
    }
    let id = g.id;
    grants.push(g);
    Ok(id)
}

pub fn prune(grants: &mut Vec<Grant>) {
    grants.retain(|x| !x.created.expired());
}

pub fn find<'a>(grants: &'a mut [Grant], id: &[u8]) -> Option<&'a mut Grant> {
    grants.iter_mut().find(|g| crypto::ct_eq(&g.id, id))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;
    use crate::vault::index::{Index, new_handle};

    fn index() -> Index {
        let mut i = Index::new([0; 16]);
        i.handles.push(new_handle(
            "stripe/live",
            "STRIPE_API_KEY",
            "",
            Mode::Approve,
            0,
        ));
        i.handles
            .push(new_handle("deny/me", "D", "", Mode::Deny, 0));
        // these tests cover the approval flow; custody (no prompt) has its own test
        for h in &mut i.handles {
            h.custody = false;
        }
        i
    }

    fn tmp_project() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "kg-grant-{}",
            crate::crypto::random_hex::<4>().unwrap()
        ));
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::canonicalize(d).unwrap()
    }

    fn req<'a>(cmd: &'a str, cwd: &'a str) -> Request<'a> {
        Request {
            command: cmd,
            cwd,
            max_runtime: None,
            capture: None,
        }
    }

    /// An allow-rule snapshot for `ls hi` pinned to `sha256` (the real hash, or a stale one).
    fn ls_rule(sha256: [u8; 32]) -> (Vec<HandlePolicy>, String) {
        let Program::File { path, .. } =
            resolve::resolve(Some("ls"), Path::new("/"), "/bin:/usr/bin")
        else {
            panic!("no ls binary")
        };
        let exe = path.to_str().unwrap().to_owned();
        let snap = vec![HandlePolicy {
            handle: "svc/key".into(),
            env_name: "SVC_KEY".into(),
            mode: Mode::Allow,
            argv: Argv::Deny,
            file: false,
            rules: vec![AllowRule {
                exe: exe.clone(),
                sha256,
                args: vec!["hi".into()],
                flags: Vec::new(),
                home: Home::Inherit,
            }],
            custody: false,
        }];
        (snap, exe)
    }

    /// Review follow-up (PR #9): a stale pin and a capture both force approval, alone or together, and the
    /// approval text names every reason.
    #[test]
    fn allow_rule_stale_pin_and_capture_each_need_approval() {
        let p = tmp_project();
        let cwd = p.to_str().unwrap();
        let Program::File { sha256: real, .. } =
            resolve::resolve(Some("ls"), Path::new("/"), "/bin:/usr/bin")
        else {
            panic!("no ls binary")
        };
        let argv = vec!["ls".to_owned(), "hi".to_owned()];
        let grant = |sha: [u8; 32], capture: Option<&str>| {
            let (snap, _) = ls_rule(sha);
            let r = Request {
                command: "ls hi",
                cwd,
                max_runtime: None,
                capture,
            };
            allow_grant(&r, &argv, &snap, &p, None, "/bin:/usr/bin", DEFAULT_RUNTIME)
                .unwrap()
                .expect("rule matches")
        };
        let stale = [7u8; 32];
        let fresh = grant(real, None);
        assert_eq!(fresh.state, State::Approved);
        for (g, repin, cap) in [
            (grant(stale, None), true, false),
            (grant(real, Some("new/handle")), false, true),
            (grant(stale, Some("new/handle")), true, true),
        ] {
            assert_eq!(g.state, State::Pending);
            assert_eq!(g.rendered.contains("re-pin"), repin, "{}", g.rendered);
            assert_eq!(g.rendered.contains("new/handle"), cap, "{}", g.rendered);
            if cap {
                assert_ne!(g.key, fresh.key, "capture target must change the grant key");
            }
        }
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn build_binds_programs_scripts_and_key() {
        let p = tmp_project();
        std::fs::write(p.join("x.sh"), b"echo hi\n").unwrap();
        let g = build(
            &req(
                "STRIPE_API_KEY={{keygent:stripe/live}} sh ./x.sh",
                p.to_str().unwrap(),
            ),
            &policy_snapshot(&index()),
            &[],
            "/usr/bin:/bin",
            None,
        )
        .unwrap();
        assert_eq!(g.handles, vec!["stripe/live"]);
        assert_eq!(g.state, State::Pending);
        assert_eq!(
            g.rewritten,
            "STRIPE_API_KEY=\"${KEYGENT_STRIPE_LIVE}\" sh \"${KEYGENT_SCRIPT_0}\""
        );
        assert_eq!(g.scripts.len(), 1);
        assert_eq!(g.scripts[0].content, b"echo hi\n");
        assert!(g.rendered.contains("echo hi") && g.rendered.contains("⚠ unbound"));
        // the key changes when the script changes
        std::fs::write(p.join("x.sh"), b"echo bye\n").unwrap();
        let g2 = build(
            &req(
                "STRIPE_API_KEY={{keygent:stripe/live}} sh ./x.sh",
                p.to_str().unwrap(),
            ),
            &policy_snapshot(&index()),
            &[],
            "/usr/bin:/bin",
            None,
        )
        .unwrap();
        assert_ne!(g.key, g2.key);
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn refusals() {
        let p = tmp_project();
        let cwd = p.to_str().unwrap();
        let e = |c: &str| {
            build(
                &req(c, cwd),
                &policy_snapshot(&index()),
                &[],
                "/usr/bin:/bin",
                None,
            )
            .err()
            .unwrap()
        };
        assert!(matches!(
            e("tool {{keygent:stripe/live}}"),
            Error::Policy(crate::error::PolicyMsg::ArgvSecret)
        ));
        assert!(matches!(
            e("X='{{keygent:stripe/live}}' t"),
            Error::Policy(crate::error::PolicyMsg::SingleQuoted)
        ));
        assert!(matches!(
            e("X={{keygent:deny/me}} t"),
            Error::Policy(crate::error::PolicyMsg::NotAllowed(_))
        ));
        assert!(matches!(
            e("X={{keygent:nope}} t"),
            Error::Policy(crate::error::PolicyMsg::UnknownHandle(_))
        ));
        assert!(matches!(
            e("echo 'x"),
            Error::Policy(crate::error::PolicyMsg::Unparsable)
        ));
        // forbidden cwd
        let r = build(
            &req("X={{keygent:stripe/live}} t", "/"),
            &policy_snapshot(&index()),
            &[],
            "/usr/bin",
            None,
        );
        assert!(matches!(
            r.err().unwrap(),
            Error::Policy(crate::error::PolicyMsg::BadCwd)
        ));
        // a script outside the project can't be bound
        let outside = std::env::temp_dir().join("kg-outside-script.sh");
        std::fs::write(&outside, b"echo x").unwrap();
        let c = format!("X={{{{keygent:stripe/live}}}} sh {}", outside.display());
        assert!(matches!(
            e(&c),
            Error::Policy(crate::error::PolicyMsg::ScriptNotBindable)
        ));
        std::fs::remove_dir_all(p).unwrap();
    }

    #[test]
    fn queue_limits_and_dedupe() {
        let p = tmp_project();
        let cwd = p.to_str().unwrap();
        let mut gs = Vec::new();
        let mk = |n: usize| {
            build(
                &req(&format!("X={{{{keygent:stripe/live}}}} echo {n}"), cwd),
                &policy_snapshot(&index()),
                &[],
                "/usr/bin:/bin",
                None,
            )
            .unwrap()
        };
        let a = insert(&mut gs, mk(1)).unwrap();
        assert_eq!(insert(&mut gs, mk(1)).unwrap(), a, "same key → same grant");
        for n in 2..=6 {
            insert(&mut gs, mk(n)).unwrap();
        }
        assert_eq!(
            gs.iter().filter(|g| g.state == State::Pending).count(),
            MAX_PER_CWD,
            "oldest from the same cwd evicted"
        );
        assert!(find(&mut gs, &a).is_none(), "the first one was evicted");
        // a command without placeholders needs no approval
        let g = build(
            &req("echo hi", cwd),
            &policy_snapshot(&index()),
            &[],
            "/usr/bin:/bin",
            None,
        )
        .unwrap();
        assert_eq!(g.state, State::Approved);
        std::fs::remove_dir_all(p).unwrap();
    }
}
