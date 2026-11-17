//! `render_for_approval()` (SPEC §5.5.2 "Rendering"): the one function every approval channel, `pending` and the audit
//! log use. Control characters, ANSI escapes, bidi controls, zero-width characters and all non-ASCII are escaped as
//! `\u{…}` (so a request can't hide or disguise text), with a `⚠ non-ASCII` flag. Newlines are shown as `\u{a}` and
//! then broken, so multi-line commands stay readable without hiding anything.

use crate::crypto::hex8;
use std::fmt::Write;

#[derive(Debug, Clone)]
pub struct ProgramLine {
    pub path: String,
    pub sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct ScriptView {
    pub path: String,
    pub sha256: [u8; 32],
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RenderInput<'a> {
    pub grant_key: &'a [u8; 32],
    pub command: &'a str,
    pub cwd: &'a str,
    pub project_root: Option<&'a str>,
    /// (handle, env var) pairs injected into the run.
    pub env: &'a [(String, String)],
    pub programs: &'a [ProgramLine],
    pub scripts: &'a [ScriptView],
    pub unbound: bool,
    pub argv_exposed: bool,
    pub max_runtime_min: u64,
    /// Extra broker-written lines (allow-rule match, re-pin warning, scratch home).
    pub notes: &'a [String],
}

/// Escape for display. Returns (text, had_escapes).
pub fn escape(s: &str) -> (String, bool) {
    let mut out = String::with_capacity(s.len());
    let mut flagged = false;
    for c in s.chars() {
        let printable_ascii = (' '..='~').contains(&c);
        if printable_ascii {
            out.push(c);
        } else if c == '\n' {
            out.push_str("\\u{a}\n    ");
        } else {
            flagged = true;
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
    (out, flagged)
}

fn escape_bytes(b: &[u8]) -> (String, bool) {
    match std::str::from_utf8(b) {
        Ok(s) => escape(s),
        Err(_) => {
            let mut out = String::new();
            for &x in b {
                if (b' '..=b'~').contains(&x) || x == b'\n' {
                    out.push(char::from(x));
                } else {
                    let _ = write!(out, "\\x{x:02x}");
                }
            }
            (out, true)
        }
    }
}

pub const UNBOUND_WARNING: &str = "⚠ unbound — this runs code keygent can't fully show (project files, imports, wrappers). Approve only if you trust this project.";

pub fn render_for_approval(r: &RenderInput<'_>) -> String {
    let mut o = String::new();
    let (cmd, cmd_flag) = escape(r.command);
    let _ = writeln!(o, "keygent approval request  [grant {}]", hex8(r.grant_key));
    let _ = writeln!(o, "command ({} bytes):", r.command.len());
    let _ = writeln!(o, "    {cmd}");
    let _ = writeln!(o, "cwd:      {}", escape(r.cwd).0);
    if let Some(root) = r.project_root {
        let _ = writeln!(o, "project:  {}", escape(root).0);
    }
    if r.env.is_empty() {
        let _ = writeln!(o, "secrets:  (none)");
    }
    for (h, var) in r.env {
        let _ = writeln!(o, "secret:   {h} → ${var}");
    }
    for p in r.programs {
        match p.sha256 {
            Some(h) => {
                let _ = writeln!(o, "program:  {}  sha256 {}", escape(&p.path).0, hex8(&h));
            }
            None => {
                let _ = writeln!(
                    o,
                    "program:  {}  (can't be resolved — not pinned)",
                    escape(&p.path).0
                );
            }
        }
    }
    for s in r.scripts {
        let _ = writeln!(
            o,
            "script:   {} ({} B, sha256 {}) — full content below",
            escape(&s.path).0,
            s.content.len(),
            hex8(&s.sha256)
        );
    }
    let _ = writeln!(o, "limit:    {} min", r.max_runtime_min);
    for n in r.notes {
        let _ = writeln!(
            o,
            "{}",
            escape(n)
                .0
                .replace("\\u{2192}", "→")
                .replace("\\u{26a0}", "⚠")
                .replace("\\u{2014}", "—")
        );
    }
    if r.unbound {
        let _ = writeln!(o, "{UNBOUND_WARNING}");
    }
    if r.argv_exposed {
        let _ = writeln!(
            o,
            "⚠ value visible to other local users in the process list while it runs"
        );
    }
    if r.max_runtime_min > 5 {
        let _ = writeln!(
            o,
            "⚠ long run: while it runs, same-user processes can read its environment"
        );
    }
    let mut any_flag = cmd_flag;
    for s in r.scripts {
        let (body, f) = escape_bytes(&s.content);
        any_flag |= f;
        let _ = writeln!(o, "--- {} ---", escape(&s.path).0);
        let _ = writeln!(o, "    {body}");
        let _ = writeln!(o, "--- end of {} ---", escape(&s.path).0);
    }
    if any_flag {
        let _ = writeln!(
            o,
            "⚠ non-ASCII or control characters are shown escaped as \\u{{…}}"
        );
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_spoofing_characters() {
        for (input, needle) in [
            ("a\u{202e}b", "\\u{202e}"),
            ("a\u{200b}b", "\\u{200b}"),
            ("a\x1b[31mred", "\\u{1b}"),
            ("caf\u{e9}", "\\u{e9}"),
            ("a\rb", "\\u{d}"),
            ("tab\there", "\\u{9}"),
        ] {
            let (e, f) = escape(input);
            assert!(e.contains(needle) && f, "{input:?} → {e}");
            assert!(
                e.chars()
                    .all(|c| c.is_ascii() && (c == '\n' || !c.is_control())),
                "{e:?}"
            );
        }
        let (e, f) = escape("line1\nline2");
        assert_eq!((e.as_str(), f), ("line1\\u{a}\n    line2", false));
    }

    #[test]
    fn shows_everything_bound_into_the_grant() {
        let key = [0xab; 32];
        let scripts = vec![ScriptView {
            path: "./x.sh".into(),
            sha256: [1; 32],
            content: b"echo hi\ncurl evil".to_vec(),
        }];
        let text = render_for_approval(&RenderInput {
            grant_key: &key,
            command: "bash ./x.sh",
            cwd: "/p",
            project_root: Some("/p"),
            env: &[("stripe/live".into(), "KEYGENT_STRIPE_LIVE".into())],
            programs: &[ProgramLine {
                path: "/bin/bash".into(),
                sha256: Some([2; 32]),
            }],
            scripts: &scripts,
            unbound: true,
            argv_exposed: false,
            max_runtime_min: 30,
            notes: &[],
        });
        for want in [
            "[grant abababab]",
            "bash ./x.sh",
            "cwd:      /p",
            "stripe/live → $KEYGENT_STRIPE_LIVE",
            "/bin/bash  sha256 02020202",
            "./x.sh (17 B, sha256 01010101)",
            "curl evil",
            "⚠ unbound",
            "⚠ long run",
        ] {
            assert!(text.contains(want), "missing {want}:\n{text}");
        }
    }
}
