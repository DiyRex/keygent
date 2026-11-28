//! Identifier rules (SPEC §4.1, §5.3, §5.6): handles, env names, reserved env names, placeholder env names and
//! collision detection. Hand-written matchers equivalent to the SPEC regexes (no regex crate).

use crate::error::{Error, Result};

pub const MAX_HANDLES: usize = 1_000;
pub const MAX_DESCRIPTION_CHARS: usize = 200;

/// `^[a-z0-9][a-z0-9._-]{0,62}(/[a-z0-9][a-z0-9._-]{0,62}){0,3}$`
pub fn valid_handle(h: &str) -> bool {
    let parts: Vec<&str> = h.split('/').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    parts.iter().all(|p| {
        let b = p.as_bytes();
        match b.split_first() {
            Some((first, rest)) => {
                b.len() <= 63
                    && (first.is_ascii_lowercase() || first.is_ascii_digit())
                    && rest.iter().all(|c| {
                        c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || matches!(c, b'.' | b'_' | b'-')
                    })
            }
            None => false,
        }
    })
}

/// A host a custody handle may reach (ADR 0022): lower-case DNS name, labels `[a-z0-9-]{1,63}` not starting or
/// ending with `-`, ≤ 253 chars, no trailing dot, no port, no wildcard (C1).
pub fn valid_host(h: &str) -> bool {
    h.len() <= 253
        && !h.is_empty()
        && h.split('.').all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b.first() != Some(&b'-')
                && b.last() != Some(&b'-')
        })
}

pub fn check_handle(h: &str) -> Result<()> {
    if valid_handle(h) {
        Ok(())
    } else {
        Err(Error::InvalidHandle)
    }
}

/// `^[A-Z_][A-Z0-9_]{0,63}$`
pub fn valid_env_name(n: &str) -> bool {
    let b = n.as_bytes();
    match b.split_first() {
        Some((first, rest)) => {
            b.len() <= 64
                && (first.is_ascii_uppercase() || *first == b'_')
                && rest
                    .iter()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        }
        None => false,
    }
}

/// Exact reserved names (SPEC §5.6). Compared case-insensitively because Windows env names are.
const RESERVED_EXACT: &[&str] = &[
    "PATH",
    "PATHEXT",
    "HOME",
    "USERPROFILE",
    "SHELL",
    "COMSPEC",
    "SYSTEMROOT",
    "IFS",
    "ENV",
    "BASH_ENV",
    "PROMPT_COMMAND",
    "SHELLOPTS",
    "NODE_OPTIONS",
    "RUBYOPT",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "TERM",
    "PAGER",
    "EDITOR",
    "VISUAL",
];

/// Reserved prefixes (SPEC §5.6): `LD_*`, `DYLD_*`, `PYTHON*`, `PERL5*`, `GIT_*`, `SSH_*`, `KEYGENT_*`.
const RESERVED_PREFIX: &[&str] = &[
    "LD_", "DYLD_", "PYTHON", "PERL5", "GIT_", "SSH_", "KEYGENT_",
];

pub fn is_reserved_env(n: &str) -> bool {
    let u = n.to_ascii_uppercase();
    RESERVED_EXACT.contains(&u.as_str()) || RESERVED_PREFIX.iter().any(|p| u.starts_with(p))
}

pub fn check_env_name(n: &str) -> Result<()> {
    if !valid_env_name(n) {
        return Err(Error::InvalidEnvName);
    }
    if is_reserved_env(n) {
        return Err(Error::ReservedEnvName(n.to_owned()));
    }
    Ok(())
}

/// Placeholder env name: `KEYGENT_` + upper-case handle with `/ . -` → `_` (SPEC §5.3).
pub fn placeholder_env(handle: &str) -> String {
    let mut s = String::with_capacity(handle.len().saturating_add(8));
    s.push_str("KEYGENT_");
    for c in handle.chars() {
        s.push(match c {
            '/' | '.' | '-' => '_',
            c => c.to_ascii_uppercase(),
        });
    }
    s
}

/// Default env name for a new handle: the handle upper-cased, `/ . -` → `_` (`stripe/live` → `STRIPE_LIVE`).
pub fn default_env_name(handle: &str) -> String {
    placeholder_env(handle).split_off("KEYGENT_".len())
}

/// The first existing handle whose placeholder env collides with `new` (case-insensitive), if any.
pub fn collision<'a>(new: &str, existing: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let p = placeholder_env(new).to_ascii_uppercase();
    existing
        .into_iter()
        .find(|h| *h != new && placeholder_env(h).eq_ignore_ascii_case(&p))
}

/// Handle derived from a `.env` key for `import`: lower-case, `_` → `-` (`STRIPE_API_KEY` → `stripe-api-key`).
pub fn handle_from_env_key(key: &str) -> Option<String> {
    let h: String = key
        .chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect();
    let h = h.trim_start_matches(['-', '.']).to_owned();
    valid_handle(&h).then_some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        for ok in [
            "stripe/live",
            "a",
            "0",
            "a.b_c-d",
            "a/b/c/d",
            &"a".repeat(63),
        ] {
            assert!(valid_handle(ok), "{ok}");
        }
        for bad in [
            "",
            "/",
            "a/",
            "/a",
            "A",
            "stripe/Live",
            "-a",
            ".a",
            "_a",
            "a/b/c/d/e",
            "a b",
            "a\u{0}",
            "é",
            &"a".repeat(64),
            "a//b",
            "a/./b",
            "a/../b",
        ] {
            assert!(!valid_handle(bad), "{bad:?}");
        }
        assert!(valid_handle(&["a".repeat(63).as_str(); 4].join("/")));
    }

    #[test]
    fn env_names() {
        assert!(valid_env_name("STRIPE_API_KEY"));
        assert!(valid_env_name("_X"));
        assert!(!valid_env_name("1X"));
        assert!(!valid_env_name("x"));
        assert!(!valid_env_name(&"A".repeat(65)));
        for r in [
            "PATH",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "PERL5LIB",
            "GIT_SSH_COMMAND",
            "SSH_AUTH_SOCK",
            "KEYGENT_X",
            "ComSpec",
            "SystemRoot",
            "BASH_ENV",
            "IFS",
            "EDITOR",
        ] {
            assert!(is_reserved_env(r), "{r}");
        }
        assert!(!is_reserved_env("STRIPE_API_KEY"));
        assert_eq!(
            check_env_name("LD_PRELOAD"),
            Err(Error::ReservedEnvName("LD_PRELOAD".into()))
        );
    }

    #[test]
    fn placeholders_and_collisions() {
        assert_eq!(placeholder_env("stripe/live"), "KEYGENT_STRIPE_LIVE");
        assert_eq!(placeholder_env("a.b-c"), "KEYGENT_A_B_C");
        assert_eq!(default_env_name("stripe/live"), "STRIPE_LIVE");
        let existing = ["stripe/live", "gh.token"];
        assert_eq!(collision("stripe.live", existing), Some("stripe/live"));
        assert_eq!(collision("stripe-live", existing), Some("stripe/live"));
        assert_eq!(collision("gh/token", existing), Some("gh.token"));
        assert_eq!(collision("stripe/test", existing), None);
        assert_eq!(collision("stripe/live", existing), None); // itself (rename to same)
    }

    #[test]
    fn import_handles() {
        assert_eq!(
            handle_from_env_key("STRIPE_API_KEY").as_deref(),
            Some("stripe-api-key")
        );
        assert_eq!(handle_from_env_key("_X").as_deref(), Some("x"));
        assert_eq!(handle_from_env_key("A B"), None);
    }
}
