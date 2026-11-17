//! Encodings a secret can appear in (SPEC §5.8): raw, base64 std/url in all 3 byte alignments, hex, percent, JSON
//! string escaping, shell quoting, UTF-16LE, and the value with surrounding quotes/whitespace stripped. Multi-line
//! values add each strong line, the PEM/base64 body unwrapped and re-wrapped at 64 and 76 columns.
//! Every output is secret-derived and returned as zeroizing buffers.

use zeroize::Zeroizing;

pub type Buf = Zeroizing<Vec<u8>>;

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX_LO: &[u8; 16] = b"0123456789abcdef";
const HEX_UP: &[u8; 16] = b"0123456789ABCDEF";

/// Table lookup; callers mask the index to the table size, `get` keeps it total anyway.
fn idx(t: &[u8], i: usize) -> u8 {
    t.get(i).copied().unwrap_or(b'?')
}

/// Base64 of `data` as if it started at byte offset `k` (0..3) of a larger stream: only the characters fully
/// determined by `data`'s own bits are returned (no padding, no partial characters at either end).
pub fn base64_core(data: &[u8], k: usize, alpha: &[u8; 64]) -> Buf {
    let mut bits = Zeroizing::new(Vec::with_capacity(data.len().saturating_add(3)));
    bits.resize(k, 0u8);
    bits.extend_from_slice(data);
    let mut full = Zeroizing::new(Vec::with_capacity(
        bits.len().saturating_mul(4).div_ceil(3).saturating_add(4),
    ));
    for chunk in bits.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for s in [18u32, 12, 6, 0] {
            full.push(idx(alpha, usize::try_from((n >> s) & 63).unwrap_or(0)));
        }
    }
    let start_bit = k.saturating_mul(8);
    let end_bit = start_bit.saturating_add(data.len().saturating_mul(8));
    let first = start_bit.div_ceil(6);
    let last = end_bit / 6;
    Zeroizing::new(
        full.get(first..last.max(first))
            .map(<[u8]>::to_vec)
            .unwrap_or_default(),
    )
}

pub fn hex(data: &[u8], table: &[u8; 16]) -> Buf {
    let mut o = Zeroizing::new(Vec::with_capacity(data.len().saturating_mul(2)));
    for &b in data {
        o.push(idx(table, usize::from(b >> 4)));
        o.push(idx(table, usize::from(b & 15)));
    }
    o
}

/// `%XX` for every byte (`all`) or only for bytes outside RFC 3986 unreserved.
pub fn percent(data: &[u8], table: &[u8; 16], all: bool) -> Buf {
    let mut o = Zeroizing::new(Vec::with_capacity(data.len().saturating_mul(3)));
    for &b in data {
        if !all && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')) {
            o.push(b);
        } else {
            o.push(b'%');
            o.push(idx(table, usize::from(b >> 4)));
            o.push(idx(table, usize::from(b & 15)));
        }
    }
    o
}

/// JSON string-body escaping; `slash` also escapes `/` as `\/` (some encoders do).
pub fn json(data: &[u8], slash: bool) -> Buf {
    let mut o = Zeroizing::new(Vec::with_capacity(data.len().saturating_mul(2)));
    for &b in data {
        match b {
            b'"' => o.extend_from_slice(b"\\\""),
            b'\\' => o.extend_from_slice(b"\\\\"),
            b'/' if slash => o.extend_from_slice(b"\\/"),
            b'\n' => o.extend_from_slice(b"\\n"),
            b'\r' => o.extend_from_slice(b"\\r"),
            b'\t' => o.extend_from_slice(b"\\t"),
            0..=0x1f => {
                o.extend_from_slice(b"\\u00");
                o.push(idx(HEX_LO, usize::from(b >> 4)));
                o.push(idx(HEX_LO, usize::from(b & 15)));
            }
            _ => o.push(b),
        }
    }
    o
}

/// POSIX single-quote body (`'` → `'\''`) and double-quote body (`$ ` " \` escaped).
pub fn shell_single(data: &[u8]) -> Buf {
    let mut o = Zeroizing::new(Vec::with_capacity(data.len().saturating_add(8)));
    for &b in data {
        if b == b'\'' {
            o.extend_from_slice(b"'\\''");
        } else {
            o.push(b);
        }
    }
    o
}

pub fn shell_double(data: &[u8]) -> Buf {
    let mut o = Zeroizing::new(Vec::with_capacity(data.len().saturating_add(8)));
    for &b in data {
        if matches!(b, b'$' | b'`' | b'"' | b'\\') {
            o.push(b'\\');
        }
        o.push(b);
    }
    o
}

/// UTF-16LE of the value's characters (invalid UTF-8 → byte-wise widening).
pub fn utf16le(data: &[u8]) -> Buf {
    let mut o = Zeroizing::new(Vec::with_capacity(data.len().saturating_mul(2)));
    match std::str::from_utf8(data) {
        Ok(s) => {
            for u in s.encode_utf16() {
                o.extend_from_slice(&u.to_le_bytes());
            }
        }
        Err(_) => {
            for &b in data {
                o.push(b);
                o.push(0);
            }
        }
    }
    o
}

pub fn stripped(data: &[u8]) -> Buf {
    let t = data.trim_ascii();
    let t = t
        .strip_prefix(b"\"")
        .and_then(|x| x.strip_suffix(b"\""))
        .unwrap_or(t);
    let t = t
        .strip_prefix(b"'")
        .and_then(|x| x.strip_suffix(b"'"))
        .unwrap_or(t);
    Zeroizing::new(t.trim_ascii().to_vec())
}

/// Every variant for one value (duplicates and too-short ones are filtered by the caller).
pub fn variants(v: &[u8]) -> Vec<Buf> {
    let mut out = vec![Zeroizing::new(v.to_vec())];
    for k in 0..3 {
        out.push(base64_core(v, k, B64_STD));
        out.push(base64_core(v, k, B64_URL));
    }
    out.push(hex(v, HEX_LO));
    out.push(hex(v, HEX_UP));
    for all in [true, false] {
        out.push(percent(v, HEX_UP, all));
        out.push(percent(v, HEX_LO, all));
    }
    out.push(json(v, false));
    out.push(json(v, true));
    out.push(shell_single(v));
    out.push(shell_double(v));
    out.push(utf16le(v));
    out.push(stripped(v));
    if v.contains(&b'\n') {
        multiline(v, &mut out);
    }
    out
}

/// Multi-line values (PEM, JSON): each line ≥ 20 chars that scores ≥ 60 bits on its own; the base64 body unwrapped
/// and re-wrapped at 64 and 76 columns (`\n` and `\r\n`).
fn multiline(v: &[u8], out: &mut Vec<Buf>) {
    let mut body = Zeroizing::new(Vec::new());
    for line in v.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line).trim_ascii();
        // PEM armor lines (`-----BEGIN … KEY-----`) are structural, never secret; registering them would redact every
        // PEM header as this handle
        let armor = line.starts_with(b"-----") && line.ends_with(b"-----");
        if !armor && line.len() >= 20 && crate::vault::strength::estimate_bits(line) >= 60.0 {
            out.push(Zeroizing::new(line.to_vec()));
        }
        if !line.starts_with(b"-----")
            && line
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            body.extend_from_slice(line);
        }
    }
    if body.len() >= 20 {
        for width in [64usize, 76] {
            for nl in [&b"\n"[..], b"\r\n"] {
                let mut w = Zeroizing::new(Vec::with_capacity(
                    body.len().saturating_add(
                        body.len()
                            .checked_div(width)
                            .unwrap_or(0)
                            .saturating_mul(2)
                            .saturating_add(2),
                    ),
                ));
                for (i, c) in body.chunks(width).enumerate() {
                    if i > 0 {
                        w.extend_from_slice(nl);
                    }
                    w.extend_from_slice(c);
                }
                out.push(w);
            }
        }
        out.push(body);
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

    fn base64_full(d: &[u8]) -> String {
        let mut o = String::new();
        for c in d.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for (i, s) in [18u32, 12, 6, 0].iter().enumerate() {
                if i <= c.len() {
                    o.push(B64_STD[((n >> s) & 63) as usize] as char);
                } else {
                    o.push('=');
                }
            }
        }
        o
    }

    #[test]
    fn base64_alignments_appear_in_real_encodings() {
        let v = b"KEYGENT_CANARY_b64Align_9xQ";
        for k in 0..3usize {
            for prefix_len in [k, k + 3, k + 6] {
                let mut stream = vec![b'z'; prefix_len];
                stream.extend_from_slice(v);
                stream.extend_from_slice(b"tail!");
                let enc = base64_full(&stream);
                let core = base64_core(v, prefix_len % 3, B64_STD);
                assert!(
                    enc.as_bytes()
                        .windows(core.len())
                        .any(|w| w == core.as_slice()),
                    "k={k} prefix={prefix_len}"
                );
                assert!(core.len() >= v.len() * 4 / 3 - 3);
            }
        }
        assert_eq!(base64_core(b"Man", 0, B64_STD).as_slice(), b"TWFu");
    }

    #[test]
    fn simple_encodings() {
        assert_eq!(hex(b"\x01\xab", HEX_LO).as_slice(), b"01ab");
        assert_eq!(percent(b"a b/", HEX_UP, false).as_slice(), b"a%20b%2F");
        assert_eq!(percent(b"ab", HEX_UP, true).as_slice(), b"%61%62");
        assert_eq!(
            json(b"a\"b\\c/\n\x01", true).as_slice(),
            b"a\\\"b\\\\c\\/\\n\\u0001"
        );
        assert_eq!(shell_single(b"it's").as_slice(), b"it'\\''s");
        assert_eq!(shell_double(b"a$b\"c").as_slice(), b"a\\$b\\\"c");
        assert_eq!(utf16le(b"ab").as_slice(), b"a\0b\0");
        assert_eq!(stripped(b"  \"secret\"\n").as_slice(), b"secret");
    }
}
