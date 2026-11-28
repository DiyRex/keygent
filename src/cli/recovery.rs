//! Recovery key encoding (SPEC §5.2): a random 256-bit key shown once as Base32 in 8 groups plus a 2-character
//! checksum group, typed back to confirm.
//!
//! Concrete choice (SPEC leaves the alphabet and grouping open; recorded in FORMATS §8): Crockford Base32
//! (`0-9 A-Z` without I, L, O, U; input maps I/L → 1 and O → 0, case-insensitive), 52 data characters (256 bits +
//! 4 zero pad bits) in groups of 7-7-7-7-6-6-6-6, then a 2-character group holding the top 10 bits of
//! `SHA-256(enc("kg/v1/recovery-check") ‖ enc(key))`. Typos are caught before any vault work.

use crate::crypto::{self, Secret};
use crate::error::{Error, Result};
use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUPS: [usize; 8] = [7, 7, 7, 7, 6, 6, 6, 6];
const DATA_CHARS: usize = 52;

fn value_of(c: u8) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|p| u8::try_from(p).ok())
}

fn checksum(key: &[u8]) -> Result<u16> {
    let h = crypto::sha256(&crypto::enc(&[b"kg/v1/recovery-check", key])?);
    let [a, b, ..] = h;
    Ok(u16::from_be_bytes([a, b]).wrapping_shr(6))
}

fn push5(out: &mut Zeroizing<String>, v: u32) {
    let i = usize::try_from(v & 31).unwrap_or(0);
    out.push(char::from(ALPHABET.get(i).copied().unwrap_or(b'0')));
}

/// Display form: `XXXXXXX-…-XXXXXX-CC`.
pub fn encode(key: &Secret) -> Result<Zeroizing<String>> {
    let k = key.expose();
    if k.len() != 32 {
        return Err(Error::Internal(50));
    }
    let mut chars = Zeroizing::new(String::with_capacity(DATA_CHARS));
    let (mut acc, mut bits) = (0u32, 0u32);
    // acc never holds more than 12 bits, so the shifts below can't overflow
    for &b in k {
        acc = acc.wrapping_shl(8) | u32::from(b);
        bits = bits.wrapping_add(8);
        while bits >= 5 {
            bits = bits.wrapping_sub(5);
            push5(&mut chars, acc.wrapping_shr(bits));
        }
        acc &= 1u32.wrapping_shl(bits).wrapping_sub(1);
    }
    if bits > 0 {
        push5(&mut chars, acc.wrapping_shl(5u32.wrapping_sub(bits)));
    }
    let mut out = Zeroizing::new(String::with_capacity(70));
    let mut it = chars.chars();
    for (i, g) in GROUPS.iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.extend(it.by_ref().take(*g));
    }
    let c = checksum(k)?;
    out.push('-');
    push5(&mut out, u32::from(c.wrapping_shr(5)));
    push5(&mut out, u32::from(c & 31));
    Ok(out)
}

/// Parse typed input (spaces/dashes ignored). Any typo → `WrongRecoveryKey` without touching the vault.
pub fn decode(input: &[u8]) -> Result<Secret> {
    let mut vals = Zeroizing::new(Vec::with_capacity(DATA_CHARS + 2));
    for &c in input {
        if matches!(c, b' ' | b'-' | b'\t') {
            continue;
        }
        vals.push(value_of(c).ok_or(Error::WrongRecoveryKey)?);
        if vals.len() > DATA_CHARS + 2 {
            return Err(Error::WrongRecoveryKey);
        }
    }
    if vals.len() != DATA_CHARS + 2 {
        return Err(Error::WrongRecoveryKey);
    }
    let mut key = Zeroizing::new(Vec::with_capacity(32));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &v in vals.iter().take(DATA_CHARS) {
        acc = acc.wrapping_shl(5) | u32::from(v);
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            key.push(
                u8::try_from(acc.wrapping_shr(bits) & 0xff).map_err(|_| Error::WrongRecoveryKey)?,
            );
            acc &= 1u32.wrapping_shl(bits).wrapping_sub(1);
        }
    }
    if key.len() != 32 || acc != 0 {
        return Err(Error::WrongRecoveryKey);
    }
    let c = u16::from(*vals.get(DATA_CHARS).ok_or(Error::WrongRecoveryKey)?).wrapping_shl(5)
        | u16::from(*vals.get(DATA_CHARS + 1).ok_or(Error::WrongRecoveryKey)?);
    if c != checksum(&key)? {
        return Err(Error::WrongRecoveryKey);
    }
    Ok(Secret::new(key.to_vec()))
}

pub fn generate() -> Result<Secret> {
    Ok(Secret::from_slice(&crypto::random::<32>()?))
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
    fn roundtrip_and_shape() {
        for _ in 0..200 {
            let k = generate().unwrap();
            let s = encode(&k).unwrap();
            let groups: Vec<&str> = s.split('-').collect();
            assert_eq!(
                groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
                vec![7, 7, 7, 7, 6, 6, 6, 6, 2]
            );
            let back = decode(s.as_bytes()).unwrap();
            assert_eq!(back.expose(), k.expose());
            // lower case, spaces and confusables accepted
            let typed = s
                .to_lowercase()
                .replace('-', " ")
                .replace('1', "l")
                .replace('0', "o");
            assert_eq!(decode(typed.as_bytes()).unwrap().expose(), k.expose());
        }
    }

    #[test]
    fn golden() {
        let k = Secret::from_slice(&[0u8; 32]);
        let s = encode(&k).unwrap();
        assert!(s.starts_with("0000000-0000000-0000000-0000000-000000-000000-000000-000000-"));
    }

    #[test]
    fn typos_rejected() {
        let k = generate().unwrap();
        let s = encode(&k).unwrap();
        let mut b = s.as_bytes().to_vec();
        b[3] = if b[3] == b'A' { b'B' } else { b'A' };
        assert_eq!(decode(&b).err(), Some(Error::WrongRecoveryKey));
        assert!(decode(&s.as_bytes()[..s.len() - 1]).is_err());
        assert!(decode(b"UUUUUUU").is_err());
        let mut long = s.as_bytes().to_vec();
        long.extend_from_slice(b"A");
        assert!(decode(&long).is_err());
    }
}
