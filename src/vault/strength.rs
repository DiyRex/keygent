//! Deterministic, pattern-aware strength estimator (SPEC §5.3), shared by secret values and passphrases.
//!
//! 1. Anything in the embedded common-password list (after lower-casing and undoing leetspeak) is rejected outright.
//! 2. The value is split into segments; each is scored at its cheapest interpretation:
//!    dictionary word = log2(dict size) + 1 bit if capitalized + 1 bit per leet substitution; year (1900–2099) or
//!    date = 7 bits; keyboard walk / sequence / repeat run = log2(len × 10); a non-dictionary letter run in human
//!    case (lower, UPPER, Capitalized) = 2 bits/char; anything else = len × log2(charset of that segment).
//!    "Anything else" segments can't be split arbitrarily (a gap never follows a gap), so random strings are not
//!    under-scored by cutting them into tiny pieces. Refinement (stricter than the SPEC text, as in zxcvbn): a single
//!    separator (`-`, `_`, `.`, `,`, space) right after a pattern costs 1 bit, so `word-word-word-word` doesn't
//!    pass the 70-bit passphrase floor on separators alone.
//! 3. The total is the sum. Only the first 256 bytes are scored (more bytes only add strength), bounding the work.
//!
//! The value is only read, never copied out; no score detail is logged (it would leak structure).

use crate::error::{Error, Result};
use std::collections::HashSet;
use std::sync::OnceLock;

pub const SECRET_MIN_BYTES: usize = 12;
pub const SECRET_MAX_BYTES: usize = 64 * 1024;
pub const SECRET_MIN_BITS: f64 = 80.0;
pub const PASSPHRASE_MIN_CHARS: usize = 16;
pub const PASSPHRASE_MIN_BITS: f64 = 70.0;
const SCORED_PREFIX: usize = 256;
const MAX_WORD: usize = 32;

static EFF: &str = include_str!("../../assets/eff_large.txt");
static COMMON: &str = include_str!("../../assets/common10k.txt");

struct Lists {
    dict: HashSet<&'static str>,
    common: HashSet<&'static str>,
    dict_bits: f64,
}

fn lists() -> &'static Lists {
    static L: OnceLock<Lists> = OnceLock::new();
    L.get_or_init(|| {
        let common: HashSet<&str> = COMMON.lines().filter(|l| !l.is_empty()).collect();
        let mut dict: HashSet<&str> = EFF.lines().filter(|l| l.len() >= 3).collect();
        dict.extend(
            common
                .iter()
                .filter(|w| w.len() >= 3 && w.bytes().any(|b| b.is_ascii_alphabetic())),
        );
        #[allow(
            clippy::cast_precision_loss,
            reason = "entropy estimates; counts far below 2^52"
        )]
        let dict_bits = (dict.len() as f64).log2();
        Lists {
            dict,
            common,
            dict_bits,
        }
    })
}

/// The EFF large wordlist (7 776 words) for generated passphrases.
pub fn eff_words() -> Vec<&'static str> {
    EFF.lines().filter(|l| !l.is_empty()).collect()
}

fn unleet(b: u8) -> (u8, bool) {
    match b {
        b'0' => (b'o', true),
        b'1' | b'!' => (b'i', true),
        b'3' => (b'e', true),
        b'4' | b'@' => (b'a', true),
        b'5' | b'$' => (b's', true),
        b'7' => (b't', true),
        _ => (b.to_ascii_lowercase(), false),
    }
}

/// Lower-cased, de-leeted form plus the number of leet substitutions. `1` is tried as both `i` and `l`.
fn normalize(seg: &[u8]) -> Vec<(String, u32)> {
    let mut a = String::with_capacity(seg.len());
    let mut leet = 0u32;
    for &b in seg {
        let (c, l) = unleet(b);
        leet = leet.saturating_add(u32::from(l));
        a.push(char::from(c));
    }
    let mut out = vec![(a.clone(), leet)];
    if seg.contains(&b'1') {
        out.push((
            a.chars()
                .zip(seg)
                .map(|(c, &o)| if o == b'1' { 'l' } else { c })
                .collect(),
            leet,
        ));
    }
    out
}

fn is_common(v: &[u8]) -> bool {
    let l = lists();
    normalize(v)
        .iter()
        .any(|(n, _)| l.common.contains(n.as_str()))
        || std::str::from_utf8(v).is_ok_and(|s| l.common.contains(s.to_ascii_lowercase().as_str()))
}

fn log2(x: f64) -> f64 {
    x.log2()
}

#[allow(
    clippy::cast_precision_loss,
    reason = "entropy estimates; counts far below 2^52"
)]
fn f(n: usize) -> f64 {
    n as f64
}

fn charset(seg: &[u8]) -> f64 {
    let (mut lo, mut up, mut di, mut sy, mut hi) = (false, false, false, false, false);
    for &b in seg {
        match b {
            b'a'..=b'z' => lo = true,
            b'A'..=b'Z' => up = true,
            b'0'..=b'9' => di = true,
            0x80..=0xff => hi = true,
            _ => sy = true,
        }
    }
    let mut n = 0.0;
    for (on, size) in [(lo, 26.0), (up, 26.0), (di, 10.0), (sy, 33.0), (hi, 128.0)] {
        if on {
            n += size;
        }
    }
    n
}

/// A run of letters only, in human case style.
fn human_letters(seg: &[u8]) -> bool {
    if seg.is_empty() || !seg.iter().all(u8::is_ascii_alphabetic) {
        return false;
    }
    let rest = seg.get(1..).unwrap_or_default();
    seg.iter().all(u8::is_ascii_lowercase)
        || seg.iter().all(u8::is_ascii_uppercase)
        || rest.iter().all(u8::is_ascii_lowercase)
}

fn gap_cost(seg: &[u8]) -> f64 {
    if human_letters(seg) {
        return 2.0 * f(seg.len());
    }
    f(seg.len()) * log2(charset(seg))
}

const KEYBOARD: [&[u8]; 4] = [
    b"1234567890-=",
    b"qwertyuiop[]",
    b"asdfghjkl;'",
    b"zxcvbnm,./",
];

fn key_pos(b: u8) -> Option<(f64, f64)> {
    let b = b.to_ascii_lowercase();
    KEYBOARD.iter().enumerate().find_map(|(r, row)| {
        row.iter()
            .position(|&c| c == b)
            .map(|c| (f(r), f(c) + f(r) * 0.5))
    })
}

fn adjacent_keys(a: u8, b: u8) -> bool {
    match (key_pos(a), key_pos(b)) {
        (Some((ra, ca)), Some((rb, cb))) => {
            (ra - rb).abs() <= 1.0 && (ca - cb).abs() <= 1.0 && a != b
        }
        _ => false,
    }
}

fn is_walk(seg: &[u8]) -> bool {
    seg.len() >= 3
        && seg
            .windows(2)
            .all(|w| matches!(w, [a, b] if adjacent_keys(*a, *b)))
}

fn is_sequence(seg: &[u8]) -> bool {
    if seg.len() < 3 || !seg.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    let d: Vec<i16> = seg
        .windows(2)
        .map(|w| match w {
            [a, b] => i16::from(*b).wrapping_sub(i16::from(*a)),
            _ => 0,
        })
        .collect();
    d.iter().all(|&x| x == 1) || d.iter().all(|&x| x == -1)
}

fn is_repeat(seg: &[u8]) -> bool {
    seg.len() >= 3 && seg.windows(2).all(|w| matches!(w, [a, b] if a == b))
}

fn digits(seg: &[u8]) -> Option<u32> {
    if seg.is_empty() || !seg.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(seg).ok()?.parse().ok()
}

fn is_year(seg: &[u8]) -> bool {
    seg.len() == 4 && digits(seg).is_some_and(|y| (1900..=2099).contains(&y))
}

fn is_date(seg: &[u8]) -> bool {
    let ok = |d: u32, m: u32| (1..=31).contains(&d) && (1..=12).contains(&m);
    match (seg.len(), digits(seg)) {
        (6, Some(v)) => {
            ok(v / 10_000, v / 100 % 100)
                || ok(v / 100 % 100, v / 10_000)
                || ok(v % 100, v / 100 % 100)
        }
        (8, Some(v)) => {
            let (a, b, c) = (v / 1_000_000, v / 10_000 % 100, v % 10_000);
            (ok(a, b) || ok(b, a)) && (1900..=2099).contains(&c)
                || (1900..=2099).contains(&(v / 10_000)) && ok(v % 100, v / 100 % 100)
        }
        _ => false,
    }
}

/// Cheapest pattern interpretation of `seg`, if any.
fn pattern_cost(seg: &[u8]) -> Option<f64> {
    let mut best: Option<f64> = None;
    let mut take = |c: f64| best = Some(best.map_or(c, |b: f64| b.min(c)));
    if seg.len() >= 3 && seg.len() <= MAX_WORD {
        let l = lists();
        for (n, leet) in normalize(seg) {
            if l.dict.contains(n.as_str()) {
                let cap = f64::from(u8::from(seg.iter().any(u8::is_ascii_uppercase)));
                take(l.dict_bits + cap + f64::from(leet));
            }
        }
    }
    if is_year(seg) || is_date(seg) {
        take(7.0);
    }
    if is_repeat(seg) || is_sequence(seg) || is_walk(seg) {
        take(log2(f(seg.len()) * 10.0));
    }
    best
}

/// Estimated entropy in bits.
pub fn estimate_bits(v: &[u8]) -> f64 {
    let v = v.get(..v.len().min(SCORED_PREFIX)).unwrap_or(v);
    let n = v.len();
    // best[i][s]: min cost to cover v[..i]; s = 0 after a pattern (or at start), 1 after a gap
    let mut best = vec![[f64::INFINITY; 2]; n.saturating_add(1)];
    if let Some(b) = best.get_mut(0) {
        b[0] = 0.0;
    }
    for j in 0..n {
        let Some(&[after_pat, after_gap]) = best.get(j) else {
            break;
        };
        let from_any = after_pat.min(after_gap);
        if from_any.is_infinite() {
            continue;
        }
        for k in j.saturating_add(1)..=n {
            let Some(seg) = v.get(j..k) else { break };
            if let Some(c) = pattern_cost(seg)
                && let Some(b) = best.get_mut(k)
            {
                b[0] = b[0].min(from_any + c);
            }
            if after_pat.is_finite() {
                let sep = j > 0 && matches!(seg, [b'-' | b'_' | b'.' | b',' | b' ']);
                let c = if sep { 1.0 } else { gap_cost(seg) };
                if let Some(b) = best.get_mut(k) {
                    b[1] = b[1].min(after_pat + c);
                }
            }
        }
    }
    best.get(n).map_or(0.0, |b| b[0].min(b[1]))
}

/// SPEC §4.1: 12 B – 64 KiB, ≥ 80 bits, not a common password.
pub fn check_secret(v: &[u8]) -> Result<()> {
    if v.len() < SECRET_MIN_BYTES || v.len() > SECRET_MAX_BYTES {
        return Err(Error::ValueSize);
    }
    if is_common(v) || estimate_bits(v) < SECRET_MIN_BITS {
        return Err(Error::TooWeak);
    }
    Ok(())
}

/// `--own-passphrase` (SPEC §4.1, §5.3 step 4): ≥ 16 chars, ≥ 70 bits, not a common password.
pub fn check_passphrase(p: &[u8]) -> Result<()> {
    let chars = std::str::from_utf8(p)
        .map(|s| s.chars().count())
        .unwrap_or(p.len());
    if chars < PASSPHRASE_MIN_CHARS || is_common(p) || estimate_bits(p) < PASSPHRASE_MIN_BITS {
        return Err(Error::PassphraseTooWeak);
    }
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

    #[test]
    fn golden_vectors() {
        // SPEC §5.3 step 3
        let p = estimate_bits(b"Passw0rd!2024");
        assert!((24.0..=36.0).contains(&p), "Passw0rd!2024 = {p}");
        let j = estimate_bits(b"john.smith1985");
        assert!((30.0..=48.0).contains(&j), "john.smith1985 = {j}");
        let k = estimate_bits(b"q8ZtK2mW9xLp4RvN7cYh3JdF6gTb1QsV");
        assert!((170.0..=200.0).contains(&k), "base62 key = {k}");
        assert_eq!(check_secret(b"Passw0rd!2024"), Err(Error::TooWeak));
        assert!(check_secret(b"q8ZtK2mW9xLp4RvN7cYh3JdF6gTb1QsV").is_ok());
    }

    #[test]
    fn patterns_score_low() {
        for weak in [
            &b"aaaaaaaaaaaaaaaaaaaa"[..],
            b"abcdefghijklmnopqrst",
            b"qwertyuiopasdfghjkl",
            b"1234567890123456",
            b"correcthorsebattery",
            b"PasswordPassword1234",
        ] {
            assert!(
                estimate_bits(weak) < 80.0,
                "{}",
                String::from_utf8_lossy(weak)
            );
        }
        assert!(check_secret(b"aaaaaaaaaaaaaaaaaaaaaaaa").is_err());
    }

    #[test]
    fn common_list_rejected() {
        assert!(is_common(b"password"));
        assert!(is_common(b"P@ssw0rd"));
        assert_eq!(check_passphrase(b"password"), Err(Error::PassphraseTooWeak));
    }

    #[test]
    fn sizes() {
        assert_eq!(check_secret(b"short"), Err(Error::ValueSize));
        assert_eq!(
            check_secret(&vec![b'x'; SECRET_MAX_BYTES + 1]),
            Err(Error::ValueSize)
        );
    }

    #[test]
    fn passphrases() {
        let words = eff_words();
        assert_eq!(words.len(), 7_776);
        let six = [
            words[11],
            words[2000],
            words[3500],
            words[5000],
            words[6500],
            words[7700],
        ]
        .join("-");
        assert!(
            check_passphrase(six.as_bytes()).is_ok(),
            "{six} = {}",
            estimate_bits(six.as_bytes())
        );
        let four = [words[11], words[2000], words[3500], words[5000]].join("-");
        assert!(estimate_bits(four.as_bytes()) < 70.0);
        assert!(check_passphrase(b"short-pass").is_err());
    }

    #[test]
    fn long_and_binary_values_bounded() {
        let pem =
            "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
                .repeat(200);
        let t = std::time::Instant::now();
        assert!(check_secret(pem.as_bytes()).is_ok());
        assert!(t.elapsed().as_secs() < 2);
        let bin: Vec<u8> = (0..=255u8)
            .cycle()
            .take(40)
            .map(|b| b.wrapping_mul(97))
            .collect();
        assert!(estimate_bits(&bin) > 80.0);
    }
}
