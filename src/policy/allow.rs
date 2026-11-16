//! Allow rules (SPEC §6.2, ADR 0007): a pinned program + argument pattern that runs **without approval**, env-only.
//!
//! - Only a single simple command with no placeholders, assignments, metacharacters, globs, `~` or `$` is eligible
//!   (§5.7 "Allow-rule path"); it runs without a shell, with exactly the tokenized argv.
//! - `args`: literals, `"*"` = exactly one argument that does not start with `-`, and an optional trailing `"**"`.
//! - Arguments after the positional pattern must each be an allowlisted flag: `--name` (no value), `--name value` with
//!   one value that does not start with `-`, or `--name=value` (value flags only). Abbreviations, unknown flags and
//!   short-flag clusters never match. `"**"` requires a non-empty `flags` list.
//! - Shells, interpreters and generic transfer tools can never take `*`/`**`.

use super::tokenize::Parsed;

/// Programs that are never wildcard-allowable (SPEC §6.2). Matched on the file name; versioned names
/// (`python3.12`) are covered by the prefix rule for interpreters.
const NEVER_WILDCARD: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "pwsh",
    "cmd",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "env",
    "xargs",
    "curl",
    "wget",
    "nc",
    "ncat",
    "socat",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "git",
    "make",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "pip",
    "pip3",
    "uv",
    "cargo",
    "go",
    "java",
    "osascript",
    "open",
    "sudo",
    "doas",
    "timeout",
    "nohup",
    "nice",
    "find",
    "awk",
    "sed",
    "busybox",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagSpec {
    pub name: String,
    pub takes_value: bool,
}

/// The argv of an eligible command (literal words only), or `None`.
pub fn eligible(p: &Parsed) -> Option<Vec<String>> {
    if p.metachar || p.substitution || p.subshell || p.heredoc || !p.placeholders.is_empty() {
        return None;
    }
    let [c] = p.commands.as_slice() else {
        return None;
    };
    if !c.assigns.is_empty() || c.argv.is_empty() {
        return None;
    }
    c.argv.iter().cloned().collect()
}

fn base_name(exe: &str) -> &str {
    exe.rsplit('/').next().unwrap_or(exe)
}

pub fn never_wildcard(exe: &str) -> bool {
    let n = base_name(exe);
    NEVER_WILDCARD.contains(&n)
        || n.starts_with("python")
        || n.starts_with("ruby")
        || n.starts_with("perl")
}

/// Validate a rule at creation time. Returns the reason it is refused.
pub fn check_shape(exe: &str, args: &[String], flags: &[FlagSpec]) -> Result<(), &'static str> {
    if !exe.starts_with('/') {
        return Err("the program must be an absolute path");
    }
    let wild = args.iter().any(|a| a == "*" || a == "**");
    if wild && never_wildcard(exe) {
        return Err("shells, interpreters and transfer tools can't take '*' or '**'");
    }
    if let Some(pos) = args.iter().position(|a| a == "**")
        && pos.saturating_add(1) != args.len()
    {
        return Err("'**' must be the last argument");
    }
    if args.last().is_some_and(|a| a == "**") && flags.is_empty() {
        return Err("'**' needs a flags allowlist");
    }
    for f in flags {
        if !f.name.starts_with("--") || f.name.len() < 3 || f.name.contains('=') {
            return Err("flags must be long options like --limit");
        }
    }
    for a in args {
        if a.is_empty() {
            return Err("empty arguments can't be matched");
        }
    }
    Ok(())
}

/// Does `argv` (without argv[0]) match the rule's pattern and flags?
pub fn matches(args: &[String], flags: &[FlagSpec], argv: &[String]) -> bool {
    let positional: &[String] = match args.last() {
        Some(l) if l == "**" => args.get(..args.len().saturating_sub(1)).unwrap_or_default(),
        _ => args,
    };
    if argv.len() < positional.len() {
        return false;
    }
    let (head, rest) = argv.split_at(positional.len());
    for (pat, a) in positional.iter().zip(head) {
        let ok = if pat == "*" {
            !a.is_empty() && !a.starts_with('-')
        } else {
            pat == a
        };
        if !ok {
            return false;
        }
    }
    let mut i = 0usize;
    while let Some(a) = rest.get(i) {
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (a.as_str(), None),
        };
        let Some(f) = flags.iter().find(|f| f.name == name) else {
            return false;
        };
        match (f.takes_value, inline) {
            (false, None) => {}
            (false, Some(_)) => return false,
            (true, Some(v)) => {
                if v.is_empty() {
                    return false;
                }
            }
            (true, None) => {
                i = i.saturating_add(1);
                match rest.get(i) {
                    Some(v) if !v.is_empty() && !v.starts_with('-') => {}
                    _ => return false,
                }
            }
        }
        i = i.saturating_add(1);
    }
    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::super::tokenize::parse;
    use super::*;

    fn v(x: &[&str]) -> Vec<String> {
        x.iter().map(|s| (*s).to_owned()).collect()
    }

    fn flags() -> Vec<FlagSpec> {
        vec![
            FlagSpec {
                name: "--limit".into(),
                takes_value: true,
            },
            FlagSpec {
                name: "--json".into(),
                takes_value: false,
            },
        ]
    }

    #[test]
    fn eligibility() {
        assert_eq!(
            eligible(&parse("stripe customers list").unwrap()),
            Some(v(&["stripe", "customers", "list"]))
        );
        for c in [
            "stripe x | cat",
            "stripe $X",
            "stripe *",
            "stripe ~/x",
            "A=1 stripe",
            "X={{keygent:a}} stripe",
            "stripe x; ls",
            "stripe > out",
            "stripe $(id)",
        ] {
            assert_eq!(eligible(&parse(c).unwrap()), None, "{c}");
        }
    }

    #[test]
    fn matching() {
        let pat = v(&["customers", "list", "*", "**"]);
        let f = flags();
        let m = |a: &[&str]| matches(&pat, &f, &v(a));
        assert!(m(&["customers", "list", "acme"]));
        assert!(m(&["customers", "list", "acme", "--limit", "3", "--json"]));
        assert!(m(&["customers", "list", "acme", "--limit=3"]));
        assert!(
            !m(&["customers", "list", "-x"]),
            "* never matches a dash argument"
        );
        assert!(!m(&["customers", "list"]));
        assert!(
            !m(&[
                "customers",
                "list",
                "acme",
                "--limit",
                "--endpoint-url",
                "evil"
            ]),
            "value can't be a flag"
        );
        assert!(
            !m(&["customers", "list", "acme", "--endpoint-url", "evil"]),
            "unknown flag"
        );
        assert!(
            !m(&["customers", "list", "acme", "--lim", "3"]),
            "abbreviation"
        );
        assert!(
            !m(&["customers", "list", "acme", "--json=1"]),
            "=value on a boolean flag"
        );
        assert!(
            !m(&["customers", "list", "acme", "--limit"]),
            "missing value"
        );
        assert!(!m(&["customers", "delete", "acme"]));
        // exact pattern without ** or flags: nothing extra allowed
        assert!(matches(&v(&["balance"]), &[], &v(&["balance"])));
        assert!(!matches(&v(&["balance"]), &[], &v(&["balance", "--json"])));
    }

    #[test]
    fn shapes() {
        let f = flags();
        assert!(
            check_shape(
                "/opt/homebrew/bin/stripe",
                &v(&["customers", "*", "**"]),
                &f
            )
            .is_ok()
        );
        assert!(check_shape("stripe", &v(&[]), &f).is_err(), "relative");
        assert!(
            check_shape("/opt/homebrew/bin/stripe", &v(&["**"]), &[]).is_err(),
            "** needs flags"
        );
        assert!(check_shape("/opt/homebrew/bin/stripe", &v(&["**", "x"]), &f).is_err());
        for exe in [
            "/bin/bash",
            "/usr/bin/python3.12",
            "/usr/bin/curl",
            "/usr/bin/git",
            "/usr/bin/env",
        ] {
            assert!(check_shape(exe, &v(&["*"]), &[]).is_err(), "{exe}");
            assert!(
                check_shape(exe, &v(&["--version"]), &[]).is_ok(),
                "{exe} literal is fine"
            );
        }
    }
}
