//! Placeholder rewrite (SPEC §5.7 "Placeholder forms", §3.2.6). Placeholders become env references by quote context;
//! the broker supplies the env at run time, so a value never appears in the command text or argv.
//!
//! - `{{keygent:<h>}}` in an argv or redirect position → refused (visible via `ps`), unless the handle has `argv = allow`.
//! - Inside `'…'` or a quoted heredoc → refused (it would not expand).
//! - `{{keygent-file:<h>}}` → `"${KEYGENT_FILE_<H>}"`, the path of a private file binding (safe in argv).

use super::tokenize::{Parsed, Quote, Role};
use crate::vault::names::placeholder_env;

#[derive(Debug, PartialEq, Eq)]
pub enum RewriteError {
    /// `keygent: secret would be visible in the process list — use {{keygent-file:<h>}} or a tool that reads $KEYGENT_<H>`
    ArgvSecret(String),
    /// `keygent: placeholder inside single quotes won't expand — use double quotes`
    SingleQuoted(String),
    /// A script word overlaps a placeholder (e.g. `sh ./{{keygent:a}}.sh`): refused as unparsable.
    Overlap,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Binding {
    pub var: String,
    pub handle: String,
    pub file: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Rewritten {
    pub cmd: String,
    pub bindings: Vec<Binding>,
}

pub fn file_var(handle: &str) -> String {
    format!(
        "KEYGENT_FILE_{}",
        placeholder_env(handle).trim_start_matches("KEYGENT_")
    )
}

/// Rewrite `cmd` (already parsed into `p`). `argv_allowed(handle)` is the per-handle `argv = allow` opt-in.
/// `extra` are further `(start, end, replacement)` edits on `cmd` (bound script words); they must not overlap
/// placeholders.
pub fn rewrite(
    cmd: &str,
    p: &Parsed,
    argv_allowed: impl Fn(&str) -> bool,
    extra: &[(usize, usize, String)],
) -> Result<Rewritten, RewriteError> {
    let mut phs = p.placeholders.clone();
    phs.sort_by_key(|x| x.start);
    let mut out = String::with_capacity(cmd.len().saturating_add(16));
    let mut bindings: Vec<Binding> = Vec::new();
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    for ph in &phs {
        if matches!(ph.quote, Quote::Single | Quote::Heredoc { quoted: true }) {
            return Err(RewriteError::SingleQuoted(ph.handle.clone()));
        }
        if !ph.file && matches!(ph.role, Role::Argv | Role::Redirect) && !argv_allowed(&ph.handle) {
            return Err(RewriteError::ArgvSecret(ph.handle.clone()));
        }
        let var = if ph.file {
            file_var(&ph.handle)
        } else {
            placeholder_env(&ph.handle)
        };
        let rep = match ph.quote {
            Quote::None => format!("\"${{{var}}}\""),
            _ => format!("${{{var}}}"),
        };
        edits.push((ph.start, ph.end, rep));
        if !bindings.iter().any(|b| b.var == var) {
            bindings.push(Binding {
                var,
                handle: ph.handle.clone(),
                file: ph.file,
            });
        }
    }
    edits.extend(extra.iter().cloned());
    edits.sort_by_key(|e| e.0);
    let mut at = 0usize;
    for (start, end, rep) in &edits {
        if *start < at || end < start {
            return Err(RewriteError::Overlap);
        }
        out.push_str(cmd.get(at..*start).ok_or(RewriteError::Overlap)?);
        out.push_str(rep);
        at = *end;
    }
    out.push_str(cmd.get(at..).ok_or(RewriteError::Overlap)?);
    Ok(Rewritten { cmd: out, bindings })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: a panic is the failure report")]
    use super::super::tokenize::parse;
    use super::*;

    fn rw(c: &str) -> Result<Rewritten, RewriteError> {
        rewrite(c, &parse(c).unwrap(), |h| h == "argv/ok", &[])
    }

    #[test]
    fn contexts() {
        assert_eq!(
            rw("STRIPE_API_KEY={{keygent:stripe/live}} stripe x")
                .unwrap()
                .cmd,
            "STRIPE_API_KEY=\"${KEYGENT_STRIPE_LIVE}\" stripe x"
        );
        assert_eq!(
            rw("tool <<< \"{{keygent:a}}\"").unwrap().cmd,
            "tool <<< \"${KEYGENT_A}\""
        );
        assert_eq!(
            rw("psql <<EOF\npw={{keygent:a}}\nEOF\n").unwrap().cmd,
            "psql <<EOF\npw=${KEYGENT_A}\nEOF\n"
        );
        let r = rw("curl -H @{{keygent-file:s/hdr}} https://x").unwrap();
        assert_eq!(r.cmd, "curl -H @\"${KEYGENT_FILE_S_HDR}\" https://x");
        assert_eq!(
            r.bindings,
            vec![Binding {
                var: "KEYGENT_FILE_S_HDR".into(),
                handle: "s/hdr".into(),
                file: true
            }]
        );
    }

    #[test]
    fn refusals() {
        assert_eq!(
            rw("tool --key {{keygent:a}}"),
            Err(RewriteError::ArgvSecret("a".into()))
        );
        assert_eq!(
            rw("tool \"--key={{keygent:a}}\""),
            Err(RewriteError::ArgvSecret("a".into()))
        );
        assert_eq!(
            rw("tool > {{keygent:a}}"),
            Err(RewriteError::ArgvSecret("a".into()))
        );
        assert_eq!(
            rw("X='{{keygent:a}}' tool"),
            Err(RewriteError::SingleQuoted("a".into()))
        );
        assert_eq!(
            rw("cat <<'E'\n{{keygent:a}}\nE"),
            Err(RewriteError::SingleQuoted("a".into()))
        );
        assert_eq!(
            rw("echo $(printf {{keygent:a}})"),
            Err(RewriteError::ArgvSecret("a".into()))
        );
        // argv opt-in
        assert_eq!(
            rw("tool --key {{keygent:argv/ok}}").unwrap().cmd,
            "tool --key \"${KEYGENT_ARGV_OK}\""
        );
    }

    #[test]
    fn extra_edits() {
        let c = "X={{keygent:a}} sh ./x.sh";
        let r = rewrite(c, &parse(c).unwrap(), |_| false, &[(19, 25, "S".into())]).unwrap();
        assert_eq!(r.cmd, "X=\"${KEYGENT_A}\" sh S");
        assert_eq!(
            rewrite(c, &parse(c).unwrap(), |_| false, &[(2, 8, "S".into())]),
            Err(RewriteError::Overlap)
        );
    }

    #[test]
    fn no_placeholders_is_identity() {
        assert_eq!(
            rw("ls -la").unwrap(),
            Rewritten {
                cmd: "ls -la".into(),
                bindings: vec![]
            }
        );
    }
}
