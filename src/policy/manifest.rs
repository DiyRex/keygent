//! Project manifest `.keygent.toml` (SPEC §5.6, FORMATS §3): a strict TOML subset, read once, hashed and parsed from
//! the same buffer. It grants nothing until the human trusts that exact content (`keygent trust`); any change
//! un-trusts it.
//!
//! ```toml
//! version = 1
//! [secrets]
//! "stripe/live" = { env = "STRIPE_API_KEY" }
//! "gcp/sa"      = { env = "GOOGLE_APPLICATION_CREDENTIALS", file = true }
//! ```
//!
//! Only these keys are accepted; anything else (unknown keys, other tables, escapes, multi-line values, duplicates)
//! is an error, so a typo can never silently grant something. Max 64 KiB, 256 entries.

use crate::vault::names;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = ".keygent.toml";
pub const MAX_BYTES: u64 = 64 * 1024;
pub const MAX_ENTRIES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub handle: String,
    pub env: String,
    pub file: bool,
}

/// A manifest as read: canonical path, SHA-256 of the exact bytes, and the parse of those bytes.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
    /// `Err(line)` when the content isn't a valid manifest (1-based line, 0 = size/encoding).
    pub entries: Result<Vec<Entry>, usize>,
}

/// Parse a quoted basic string (no escapes) or a bare key at the start of `s`; returns it and the rest.
fn key_or_string(s: &str, bare: bool) -> Option<(String, &str)> {
    if let Some(r) = s.strip_prefix('"') {
        let end = r.find('"')?;
        let v = r.get(..end)?;
        if v.contains('\\') || v.chars().any(char::is_control) {
            return None;
        }
        return Some((v.to_owned(), r.get(end.saturating_add(1)..)?));
    }
    if !bare {
        return None;
    }
    let n = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(s.len());
    if n == 0 {
        return None;
    }
    Some((s.get(..n)?.to_owned(), s.get(n..)?))
}

/// Strip a trailing `# comment` (outside quotes) and surrounding whitespace.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return line.get(..i).unwrap_or_default().trim(),
            _ => {}
        }
    }
    line.trim()
}

/// `{ env = "NAME", file = true }`
fn inline_table(s: &str) -> Option<(String, bool)> {
    let body = s.strip_prefix('{')?.strip_suffix('}')?.trim();
    let mut env = None;
    let mut file = None;
    for part in body.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        let (k, rest) = key_or_string(part, true)?;
        let v = rest.trim_start().strip_prefix('=')?.trim();
        match k.as_str() {
            "env" if env.is_none() => {
                let (val, tail) = key_or_string(v, false)?;
                if !tail.trim().is_empty() {
                    return None;
                }
                env = Some(val);
            }
            "file" if file.is_none() => {
                file = Some(match v {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                });
            }
            _ => return None,
        }
    }
    Some((env?, file.unwrap_or(false)))
}

/// Parse the exact bytes. `Err(line)` names the first bad line (0 = size or encoding).
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, usize> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        return Err(0);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| 0usize)?;
    let mut version = false;
    let mut in_secrets = false;
    let mut out: Vec<Entry> = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let n = i.saturating_add(1);
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if line == "[secrets]" {
            if in_secrets || !version {
                return Err(n);
            }
            in_secrets = true;
            continue;
        }
        if !in_secrets {
            let (k, rest) = key_or_string(line, true).ok_or(n)?;
            if k != "version"
                || version
                || rest.trim_start().strip_prefix('=').map(str::trim) != Some("1")
            {
                return Err(n);
            }
            version = true;
            continue;
        }
        let (handle, rest) = key_or_string(line, true).ok_or(n)?;
        let v = rest.trim_start().strip_prefix('=').ok_or(n)?.trim();
        let (env, file) = inline_table(v).ok_or(n)?;
        if !names::valid_handle(&handle)
            || names::check_env_name(&env).is_err()
            || out.iter().any(|e| e.handle == handle || e.env == env)
            || out.len() >= MAX_ENTRIES
        {
            return Err(n);
        }
        out.push(Entry { handle, env, file });
    }
    if !version {
        return Err(1);
    }
    Ok(out)
}

/// Find the manifest for `cwd`: the nearest `.keygent.toml` walking up, stopping at the repo root (the first
/// ancestor with `.git`, inclusive). Read once (size-capped, regular file, no symlink), hashed and parsed.
pub fn find(cwd: &Path) -> Option<Manifest> {
    for dir in cwd.ancestors() {
        let p = dir.join(FILE_NAME);
        if let Ok(m) = std::fs::symlink_metadata(&p)
            && m.is_file()
        {
            return read(&p);
        }
        if dir.join(".git").exists() {
            return None;
        }
    }
    None
}

pub fn read(p: &Path) -> Option<Manifest> {
    use std::io::Read;
    let path = std::fs::canonicalize(p).ok()?;
    let f = std::fs::File::open(&path).ok()?;
    let mut bytes = Vec::new();
    f.take(MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    let sha256 = crate::crypto::sha256(&bytes);
    let entries = parse(&bytes);
    Some(Manifest {
        path,
        sha256,
        bytes,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_subset() {
        let m = b"# project secrets\nversion = 1\n\n[secrets]\n\"stripe/live\" = { env = \"STRIPE_API_KEY\" } # ok\ngcp = { env = \"GOOGLE_APPLICATION_CREDENTIALS\", file = true }\n";
        assert_eq!(
            parse(m),
            Ok(vec![
                Entry {
                    handle: "stripe/live".into(),
                    env: "STRIPE_API_KEY".into(),
                    file: false
                },
                Entry {
                    handle: "gcp".into(),
                    env: "GOOGLE_APPLICATION_CREDENTIALS".into(),
                    file: true
                },
            ])
        );
    }

    #[test]
    fn rejects_everything_else() {
        for (m, line) in [
            ("[secrets]\n\"a\" = { env = \"A_B\" }\n", 1),
            ("version = 2\n", 1),
            ("version = 1\n[other]\n", 2),
            (
                "version = 1\n[secrets]\n\"a\" = { env = \"A\", extra = 1 }\n",
                3,
            ),
            ("version = 1\n[secrets]\n\"a\" = { env = \"PATH\" }\n", 3),
            (
                "version = 1\n[secrets]\n\"a\" = { env = \"LD_PRELOAD\" }\n",
                3,
            ),
            (
                "version = 1\n[secrets]\n\"a\" = { env = \"A\" }\n\"a\" = { env = \"B\" }\n",
                4,
            ),
            (
                "version = 1\n[secrets]\n\"a\" = { env = \"A\" }\n\"b\" = { env = \"A\" }\n",
                4,
            ),
            (
                "version = 1\n[secrets]\n\"Bad Handle\" = { env = \"A\" }\n",
                3,
            ),
            ("version = 1\n[secrets]\n\"a\" = { env = \"A\\\"\" }\n", 3),
            ("version = 1\n[secrets]\n\"a\" = { file = true }\n", 3),
            ("version = 1\nsecrets.a = 1\n", 2),
        ] {
            assert_eq!(parse(m.as_bytes()), Err(line), "{m:?}");
        }
        assert_eq!(parse(&vec![b'#'; 70_000]), Err(0));
        assert_eq!(parse(b"\xff"), Err(0));
    }
}
