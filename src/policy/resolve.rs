//! Executable resolution and hashing (SPEC §5.5.2 "Executable binding"). Every command word is resolved against the
//! PATH captured at unseal (never the client's), hashed, shown in the approval and re-checked before exec.
//! Results are cached by (dev, inode, size, mtime, ctime) — ctime can't be set by users.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Executables larger than this are refused (and never hashed).
pub const MAX_EXE: u64 = 512 * 1024 * 1024;

/// POSIX `sh` special and regular builtins we accept as command words (they have no file to pin).
const BUILTINS: &[&str] = &[
    "cd", "echo", "printf", "test", "[", "true", "false", ":", "exit", "export", "read", "set",
    "unset", "shift", "return", "wait", "pwd", "umask", "command", "type", "getopts", "trap",
    "eval", ".", "source", "exec", "alias",
];

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Program {
    Builtin(String),
    File {
        path: PathBuf,
        sha256: [u8; 32],
    },
    /// Not resolvable (expansion in the command word, missing file, not executable).
    Unknown(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

static CACHE: Mutex<Option<HashMap<Key, [u8; 32]>>> = Mutex::new(None);

fn key(m: &std::fs::Metadata) -> Key {
    Key {
        dev: m.dev(),
        ino: m.ino(),
        size: m.size(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}

/// SHA-256 of a regular file (cached). `None` if it isn't a regular file or is too large.
pub fn hash_file(p: &Path) -> Option<[u8; 32]> {
    let f = std::fs::File::open(p).ok()?;
    let m = f.metadata().ok()?;
    if !m.is_file() || m.size() > MAX_EXE {
        return None;
    }
    let k = key(&m);
    if let Some(h) = CACHE.lock().ok()?.as_ref().and_then(|c| c.get(&k)) {
        return Some(*h);
    }
    let mut buf = Vec::with_capacity(usize::try_from(m.size()).ok()?);
    f.take(MAX_EXE).read_to_end(&mut buf).ok()?;
    let h = crate::crypto::sha256(&buf);
    if let Ok(mut g) = CACHE.lock() {
        g.get_or_insert_with(HashMap::new).insert(k, h);
    }
    Some(h)
}

fn executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.mode() & 0o111 != 0)
}

/// Resolve a command word: builtins, then words with `/` (relative to `cwd`), then the captured `path_var`.
pub fn resolve(word: Option<&str>, cwd: &Path, path_var: &str) -> Program {
    let Some(w) = word else {
        return Program::Unknown("(expansion)".into());
    };
    if BUILTINS.contains(&w) {
        return Program::Builtin(w.to_owned());
    }
    let candidate = if w.contains('/') {
        let p = if Path::new(w).is_absolute() {
            PathBuf::from(w)
        } else {
            cwd.join(w)
        };
        Some(p)
    } else {
        path_var
            .split(':')
            .filter(|d| Path::new(d).is_absolute())
            .map(|d| Path::new(d).join(w))
            .find(|p| executable(p))
    };
    let Some(c) = candidate else {
        return Program::Unknown(w.to_owned());
    };
    let Ok(canon) = std::fs::canonicalize(&c) else {
        return Program::Unknown(w.to_owned());
    };
    if !executable(&canon) {
        return Program::Unknown(w.to_owned());
    }
    match hash_file(&canon) {
        Some(sha256) => Program::File {
            path: canon,
            sha256,
        },
        None => Program::Unknown(w.to_owned()),
    }
}

/// Interpreters whose first non-flag argument is a script file to bind (SPEC §5.5.2 "Script binding").
pub fn is_script_interpreter(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        base,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "python"
            | "node"
            | "ruby"
            | "perl"
            | "deno"
            | "bun"
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn resolves_and_hashes() {
        let p = resolve(Some("sh"), Path::new("/"), "/usr/bin:/bin");
        match p {
            Program::File { path, sha256 } => {
                assert!(path.is_absolute());
                assert_eq!(hash_file(&path), Some(sha256));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            resolve(Some("cd"), Path::new("/"), ""),
            Program::Builtin("cd".into())
        );
        assert!(matches!(
            resolve(Some("definitely-not-a-tool-kg"), Path::new("/"), "/usr/bin"),
            Program::Unknown(_)
        ));
        assert!(matches!(
            resolve(None, Path::new("/"), "/usr/bin"),
            Program::Unknown(_)
        ));
        // relative PATH entries (an agent-steerable ".") are ignored
        assert!(matches!(
            resolve(Some("sh"), Path::new("/"), ".:relative"),
            Program::Unknown(_)
        ));
    }

    #[test]
    fn interpreters() {
        for i in [
            "/bin/sh",
            "/usr/bin/python3",
            "/usr/bin/python3.12",
            "/opt/homebrew/bin/node",
            "/bin/bash",
        ] {
            assert!(is_script_interpreter(Path::new(i)), "{i}");
        }
        assert!(!is_script_interpreter(Path::new(
            "/opt/homebrew/bin/stripe"
        )));
    }
}
