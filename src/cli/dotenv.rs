//! `.env` parser for `keygent import` (SPEC §5.1). Total, capped, and never echoes values: errors carry only a
//! line number. Supported: `KEY=value`, `export KEY=value`, `# comments`, `"double"` (escapes `\n \r \t \" \\`,
//! may span lines) and `'single'` (literal) quoting, and unquoted values with ` #` trailing comments.

use crate::crypto::Secret;
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
}

pub struct Item {
    pub key: String,
    pub value: Secret,
}

fn valid_key(k: &[u8]) -> bool {
    matches!(k.first(), Some(c) if c.is_ascii_alphabetic() || *c == b'_')
        && k.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

pub fn parse(src: &[u8]) -> Result<Vec<Item>, ParseError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    let at = |i: usize| src.get(i).copied();
    while i < src.len() {
        // skip blank space and blank lines
        while matches!(at(i), Some(b' ' | b'\t' | b'\r')) {
            i = i.saturating_add(1);
        }
        match at(i) {
            None => break,
            Some(b'\n') => {
                i = i.saturating_add(1);
                line = line.saturating_add(1);
                continue;
            }
            Some(b'#') => {
                while !matches!(at(i), None | Some(b'\n')) {
                    i = i.saturating_add(1);
                }
                continue;
            }
            _ => {}
        }
        let start_line = line;
        let err = ParseError { line: start_line };
        if src.get(i..).is_some_and(|r| r.starts_with(b"export ")) {
            i = i.saturating_add(7);
            while matches!(at(i), Some(b' ' | b'\t')) {
                i = i.saturating_add(1);
            }
        }
        let ks = i;
        while matches!(at(i), Some(c) if c != b'=' && c != b'\n') {
            i = i.saturating_add(1);
        }
        if at(i) != Some(b'=') {
            return Err(err);
        }
        let key = src.get(ks..i).ok_or(ParseError { line: start_line })?;
        let key = key.strip_suffix(b" ").unwrap_or(key);
        if !valid_key(key) {
            return Err(err);
        }
        let key = String::from_utf8(key.to_vec()).map_err(|_| ParseError { line: start_line })?;
        i = i.saturating_add(1);
        let mut val = Zeroizing::new(Vec::new());
        match at(i) {
            Some(b'"') => {
                i = i.saturating_add(1);
                loop {
                    match at(i) {
                        None => return Err(err),
                        Some(b'"') => {
                            i = i.saturating_add(1);
                            break;
                        }
                        Some(b'\\') => {
                            let c =
                                at(i.saturating_add(1)).ok_or(ParseError { line: start_line })?;
                            val.push(match c {
                                b'n' => b'\n',
                                b'r' => b'\r',
                                b't' => b'\t',
                                c => c,
                            });
                            i = i.saturating_add(2);
                        }
                        Some(c) => {
                            if c == b'\n' {
                                line = line.saturating_add(1);
                            }
                            val.push(c);
                            i = i.saturating_add(1);
                        }
                    }
                }
            }
            Some(b'\'') => {
                i = i.saturating_add(1);
                loop {
                    match at(i) {
                        None => return Err(err),
                        Some(b'\'') => {
                            i = i.saturating_add(1);
                            break;
                        }
                        Some(c) => {
                            if c == b'\n' {
                                line = line.saturating_add(1);
                            }
                            val.push(c);
                            i = i.saturating_add(1);
                        }
                    }
                }
            }
            _ => {
                while let Some(c) = at(i) {
                    if c == b'\n' || (c == b'#' && matches!(val.last(), Some(b' ' | b'\t'))) {
                        break;
                    }
                    val.push(c);
                    i = i.saturating_add(1);
                }
                while matches!(val.last(), Some(b' ' | b'\t' | b'\r')) {
                    val.pop();
                }
                while matches!(val.first(), Some(b' ' | b'\t')) {
                    val.remove(0);
                }
            }
        }
        // rest of the line may hold only whitespace or a comment
        while matches!(at(i), Some(b' ' | b'\t' | b'\r')) {
            i = i.saturating_add(1);
        }
        match at(i) {
            None | Some(b'\n') => {}
            Some(b'#') => {
                while !matches!(at(i), None | Some(b'\n')) {
                    i = i.saturating_add(1);
                }
            }
            Some(_) => return Err(err),
        }
        out.push(Item {
            key,
            value: Secret::new(val.to_vec()),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn parses_common_forms() {
        let src = b"# c\nA=plain value # comment\nexport B=\"line1\\nline2\"\nC='lit $x \\n'\n\nD=\"multi\nline\"\nE=x#y\n";
        let v = parse(src).unwrap();
        let got: Vec<(String, Vec<u8>)> = v
            .iter()
            .map(|i| (i.key.clone(), i.value.expose().to_vec()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("A".into(), b"plain value".to_vec()),
                ("B".into(), b"line1\nline2".to_vec()),
                ("C".into(), b"lit $x \\n".to_vec()),
                ("D".into(), b"multi\nline".to_vec()),
                ("E".into(), b"x#y".to_vec()),
            ]
        );
    }

    #[test]
    fn errors_name_only_the_line() {
        assert_eq!(
            parse(b"A=1\nnot a pair\n").err(),
            Some(ParseError { line: 2 })
        );
        assert_eq!(
            parse(b"A=\"unterminated").err(),
            Some(ParseError { line: 1 })
        );
        assert_eq!(parse(b"1A=x").err(), Some(ParseError { line: 1 }));
        assert_eq!(parse(b"A=\"x\" junk").err(), Some(ParseError { line: 1 }));
    }

    #[test]
    fn never_panics() {
        let mut x: u32 = 1;
        for _ in 0..5000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let alphabet = b"AB_=\"'\\\n #x";
            let s: Vec<u8> = (0..(x % 24))
                .map(|i| alphabet[((x >> (i % 24)) as usize) % alphabet.len()])
                .collect();
            let _ = parse(&s);
        }
    }
}
