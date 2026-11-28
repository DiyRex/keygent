//! Credential custody (ADR 0022): the child gets a **dummy** shaped like the value, never the value itself.
//!
//! The dummy keeps the value's length and the character class at every position, so tools that check a token's format
//! accept it. It also keeps a leading public prefix (`dop_v1_`, `sk_live_`, `ghp_`, `xoxb-`) when what follows is still a
//! strong secret on its own, so the prefix can't give away part of a password-like value. Everything else is random.

use crate::crypto;
use crate::error::Result;
use crate::vault::strength;

/// At most this many prefix tokens (`dop_` + `v1_`) and characters are kept.
const PREFIX_TOKENS: usize = 3;
const PREFIX_MAX: usize = 12;
/// The part after the prefix must still score this many bits on its own, or no prefix is kept.
const REST_MIN_BITS: f64 = 64.0;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &[u8] = b"0123456789";
const HEX_LOWER: &[u8] = b"abcdef";
const HEX_UPPER: &[u8] = b"ABCDEF";

/// Length of the public prefix kept in the dummy: up to 3 tokens of `[A-Za-z0-9]{1,8}` that contain a letter, each
/// followed by `_` or `-`, at most 12 bytes, and only if the rest is still strong (≥ 64 bits).
pub fn prefix_len(v: &[u8]) -> usize {
    let mut end = 0usize;
    for _ in 0..PREFIX_TOKENS {
        let rest = v.get(end..).unwrap_or_default();
        let word = rest
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        let has_letter = rest
            .get(..word)
            .is_some_and(|w| w.iter().any(u8::is_ascii_alphabetic));
        let sep = rest.get(word).is_some_and(|b| matches!(b, b'_' | b'-'));
        if word == 0 || word > 8 || !has_letter || !sep {
            break;
        }
        let next = end.saturating_add(word).saturating_add(1);
        if next > PREFIX_MAX {
            break;
        }
        end = next;
    }
    let rest = v.get(end..).unwrap_or_default();
    if end > 0 && strength::estimate_bits(rest) < REST_MIN_BITS {
        return 0;
    }
    end
}

/// A fresh dummy for `v`: same length, same class per position (lower, upper, digit; other bytes kept as-is so
/// separators survive), prefix kept per [`prefix_len`]. Never equal to `v`. If every letter after the prefix is a
/// hex digit, letters stay hex (a token format check like "64 hex chars" still passes).
pub fn dummy(v: &[u8]) -> Result<Vec<u8>> {
    let keep = prefix_len(v);
    let rest = v.get(keep..).unwrap_or_default();
    let lower: &[u8] = if rest
        .iter()
        .filter(|b| b.is_ascii_lowercase())
        .all(|b| b.is_ascii_hexdigit())
    {
        HEX_LOWER
    } else {
        LOWER
    };
    let upper: &[u8] = if rest
        .iter()
        .filter(|b| b.is_ascii_uppercase())
        .all(|b| b.is_ascii_hexdigit())
    {
        HEX_UPPER
    } else {
        UPPER
    };
    loop {
        let mut out = Vec::with_capacity(v.len());
        for (i, &b) in v.iter().enumerate() {
            let class: Option<&[u8]> = if i < keep {
                None
            } else if b.is_ascii_lowercase() {
                Some(lower)
            } else if b.is_ascii_uppercase() {
                Some(upper)
            } else if b.is_ascii_digit() {
                Some(DIGIT)
            } else {
                None
            };
            out.push(match class {
                Some(set) => {
                    let n = u32::try_from(set.len()).unwrap_or(1);
                    let k = usize::try_from(crypto::random_below(n)?).unwrap_or(0);
                    set.get(k).copied().unwrap_or(b'x')
                }
                None => b,
            });
        }
        if !crypto::ct_eq(&out, v) {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    fn class(b: u8) -> u8 {
        if b.is_ascii_lowercase() {
            b'a'
        } else if b.is_ascii_uppercase() {
            b'A'
        } else if b.is_ascii_digit() {
            b'0'
        } else {
            b
        }
    }

    #[test]
    fn keeps_shape_and_public_prefix() {
        for (v, prefix) in [
            (
                concat!(
                    "dop_",
                    "v1_4f9a1c0e7b2d8f3a6c5e9b1d0a7f4c2e8b3d6f9a1c4e7b0d2f5a8c1e3b6d9f0a"
                )
                .as_bytes(),
                7,
            ),
            (
                concat!("sk_", "live_51Hq8ZtR2mVx9KpL4wNc7YdJ0bTf3GsQ6").as_bytes(),
                8,
            ),
            (
                concat!("gh", "p_Xk92LmQ7vT4zRw8NcB1yHd6PfJ3sGa5EuK0o").as_bytes(),
                4,
            ),
            (
                concat!("xo", "xb-7302918465-Qm4Zr8TxL2wVn6KcY9pB").as_bytes(),
                5,
            ),
            (concat!("AK", "IAIOSFODNN7EXAMPLEZZ").as_bytes(), 0),
        ] {
            assert_eq!(prefix_len(v), prefix, "{}", String::from_utf8_lossy(v));
            let d = dummy(v).unwrap();
            assert_eq!(d.len(), v.len());
            assert_eq!(&d[..prefix], &v[..prefix]);
            assert_ne!(d, v);
            assert!(d.iter().zip(v).all(|(a, b)| class(*a) == class(*b)));
            // fresh per call
            assert_ne!(dummy(v).unwrap(), d);
        }
    }

    #[test]
    fn hex_values_get_hex_dummies() {
        let v = concat!(
            "dop_",
            "v1_4f9a1c0e7b2d8f3a6c5e9b1d0a7f4c2e8b3d6f9a1c4e7b0d2f5a8c1e3b6d9f0a"
        )
        .as_bytes();
        for _ in 0..20 {
            let d = dummy(v).unwrap();
            assert!(
                d[7..].iter().all(u8::is_ascii_hexdigit),
                "{}",
                String::from_utf8_lossy(&d)
            );
        }
        let d = dummy(b"9F3A0C7E1B5D2F8A6C4E0B9D7F1A3C5E").unwrap();
        assert!(
            d.iter()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b))
        );
    }

    #[test]
    fn password_like_values_keep_no_prefix() {
        // the words after the "prefix" are not a strong secret on their own, so nothing is kept
        // (test vectors are split with concat! so secret scanners don't flag the source)
        let v = b"correct_horse_battery";
        assert_eq!(prefix_len(v), 0);
        let d = dummy(v).unwrap();
        assert_ne!(&d[..8], b"correct_");
        assert_eq!(d[7], b'_');
    }
}
