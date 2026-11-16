//! Streaming multi-pattern redactor (SPEC §5.8), constructed only by `broker/`.
//!
//! - Every vault value is registered in all encodings from `encode` (≥ 8 bytes each). Matching uses a 512 Kibit
//!   filter on each position's first 4 bytes and an exact 8-byte prefix index, then a full comparison.
//! - **Hold-back rule** (SPEC §5.7.5): bytes that could still be the start of a match are never emitted until the match
//!   completes or becomes impossible. At EOF a held tail of ≥ 6 bytes that is the start of a secret is redacted too
//!   (stricter than SPEC: a truncated secret never leaks its prefix).
//! - Generic detectors (AWS, GitHub, Stripe, Slack, JWT, PEM) catch secrets that aren't in the vault → `‹keygent:unknown›`.
//! - Pattern bytes are secret-derived: kept in `Secret`s (locked arena in the broker); total ≤ 8 MiB (SPEC §5.8).

pub mod encode;

use crate::crypto::Secret;
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

pub const MIN_PATTERN: usize = 8;
pub const MAX_PATTERN_BYTES: usize = 8 * 1024 * 1024;
/// A held tail this long that is the start of a secret is redacted at EOF.
const EOF_PARTIAL_MIN: usize = 6;
const FILTER_BITS: usize = 1 << 19;
/// Generic detectors never hold back more than this (PEM blocks).
const MAX_DETECT: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum BuildError {
    /// `keygent: too many or too large secrets to redact safely — remove some or split vaults`
    TooLarge,
}

struct Pat {
    bytes: Secret,
    handle: u32,
}

pub struct Redactor {
    pats: Vec<Pat>,
    prefix8: HashMap<u64, Vec<u32>>,
    filter: Vec<u64>,
    /// `short[k]` holds every pattern's first `k` bytes (k = 1..7), packed little-endian, for hold-back near the end.
    short: Vec<HashSet<u64>>,
    handles: Vec<String>,
}

fn pack(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    for (d, s) in a.iter_mut().zip(b) {
        *d = *s;
    }
    u64::from_le_bytes(a)
}

#[inline(always)]
fn h4(b: &[u8]) -> usize {
    let x = match b.first_chunk::<4>() {
        Some(c) => u32::from_le_bytes(*c),
        None => u32::try_from(pack(b) & 0xffff_ffff).unwrap_or(0),
    };
    usize::try_from(x.wrapping_mul(0x9E37_79B1) >> 13).unwrap_or(0) & (FILTER_BITS - 1)
}

/// Two-byte starts of the generic detectors (`AK`/`AS`, `gh`/`gi`, `sk`/`rk`, `xo`, `ey`, `--`), as a 64 Kibit set.
/// Normal text rarely contains them, so the full matcher runs at very few positions.
#[allow(clippy::indexing_slicing)] // compile-time table; an out-of-range index is a build error
const DETECT2: [u64; 1024] = {
    let mut t = [0u64; 1024];
    let pairs: [[u8; 2]; 9] = [
        *b"AK", *b"AS", *b"gh", *b"gi", *b"sk", *b"rk", *b"xo", *b"ey", *b"--",
    ];
    let mut i = 0;
    while i < pairs.len() {
        let v = (pairs[i][0] as usize) | ((pairs[i][1] as usize) << 8);
        t[v / 64] |= 1u64 << (v % 64);
        i += 1;
    }
    t
};

#[inline(always)]
fn detect2(a: u8, b: u8) -> bool {
    let v = usize::from(a) | (usize::from(b) << 8);
    DETECT2
        .get(v / 64)
        .is_some_and(|w| w & (1u64 << (v % 64)) != 0)
}

/// A truncated tail held at EOF is redacted only if it carries real entropy (structural text like a PEM header
/// that happens to begin a vault value is not secret).
const EOF_PARTIAL_BITS: f64 = 48.0;

/// Pattern bytes a value would add (for the 8 MiB cap check at `add`/`import`/`rotate`, without building anything).
pub fn pattern_bytes(value: &[u8]) -> usize {
    encode::variants(value)
        .iter()
        .filter(|v| v.len() >= MIN_PATTERN)
        .map(|v| v.len())
        .sum()
}

enum Hit {
    None,
    Full(usize, Option<u32>),
    /// Could still become a match. `vault` = the start of a vault value (secret bytes), not a detector's fixed prefix.
    Partial {
        vault: bool,
        handle: Option<u32>,
    },
}

impl Redactor {
    /// Build from `(handle, value)` pairs (current and previous values). Fails if pattern bytes exceed 8 MiB.
    pub fn new<'a>(
        secrets: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<Redactor, BuildError> {
        let mut r = Redactor {
            pats: Vec::new(),
            prefix8: HashMap::new(),
            filter: vec![0u64; FILTER_BITS / 64],
            short: (0..8).map(|_| HashSet::new()).collect(),
            handles: Vec::new(),
        };
        let mut total = 0usize;
        for (handle, value) in secrets {
            let hid = match r.handles.iter().position(|h| h == handle) {
                Some(i) => i,
                None => {
                    r.handles.push(handle.to_owned());
                    r.handles.len().saturating_sub(1)
                }
            };
            let hid = u32::try_from(hid).map_err(|_| BuildError::TooLarge)?;
            for v in encode::variants(value) {
                if v.len() < MIN_PATTERN {
                    continue;
                }
                // dedupe against registered patterns (no second plaintext copy for a "seen" set)
                let key = pack(v.get(..8).unwrap_or(&v));
                let dup = r.prefix8.get(&key).is_some_and(|c| {
                    c.iter().any(|&pi| {
                        r.pats
                            .get(usize::try_from(pi).unwrap_or(usize::MAX))
                            .is_some_and(|p| p.bytes.expose() == v.as_slice())
                    })
                });
                if dup {
                    continue;
                }
                total = total.saturating_add(v.len());
                if total > MAX_PATTERN_BYTES {
                    return Err(BuildError::TooLarge);
                }
                let idx = u32::try_from(r.pats.len()).map_err(|_| BuildError::TooLarge)?;
                let bit = h4(&v);
                if let Some(w) = r.filter.get_mut(bit / 64) {
                    *w |= 1u64 << (bit % 64);
                }
                r.prefix8.entry(key).or_default().push(idx);
                for k in 1..8 {
                    if let (Some(set), Some(p)) = (r.short.get_mut(k), v.get(..k)) {
                        set.insert(pack(p));
                    }
                }
                r.pats.push(Pat {
                    bytes: Secret::from_slice(&v),
                    handle: hid,
                });
            }
        }
        Ok(r)
    }

    fn token(&self, h: Option<u32>) -> Vec<u8> {
        let name = h
            .and_then(|i| self.handles.get(usize::try_from(i).ok()?))
            .map_or("unknown", String::as_str);
        format!("‹keygent:{name}›").into_bytes()
    }

    #[inline(always)]
    fn filter_hit(&self, b: &[u8]) -> bool {
        let bit = h4(b);
        self.filter
            .get(bit / 64)
            .is_some_and(|w| w & (1u64 << (bit % 64)) != 0)
    }

    /// What starts at `buf[i..]`: the longest complete match, or "could still match" (partial).
    fn find(&self, buf: &[u8], i: usize) -> Hit {
        let Some(rest) = buf.get(i..) else {
            return Hit::None;
        };
        let mut best: Option<(usize, Option<u32>)> = None;
        let mut partial: Option<Option<u32>> = None;
        let mut detector_partial = false;
        if rest.len() >= MIN_PATTERN {
            if self.filter_hit(rest)
                && let Some(c) = self.prefix8.get(&pack(rest.get(..8).unwrap_or_default()))
            {
                for &pi in c {
                    let Some(p) = self.pats.get(usize::try_from(pi).unwrap_or(usize::MAX)) else {
                        continue;
                    };
                    let pb = p.bytes.expose();
                    if pb.len() <= rest.len() {
                        if rest.get(..pb.len()) == Some(pb)
                            && best.is_none_or(|(l, _)| pb.len() > l)
                        {
                            best = Some((pb.len(), Some(p.handle)));
                        }
                    } else if pb.get(..rest.len()) == Some(rest) {
                        partial = Some(Some(p.handle));
                    }
                }
            }
        } else if (rest.len() < 4 || self.filter_hit(rest))
            && self
                .short
                .get(rest.len())
                .is_some_and(|s| s.contains(&pack(rest)))
        {
            partial = Some(None);
        }
        match detect(rest) {
            Detect::Full(l) if best.is_none_or(|(b, _)| l > b) => best = Some((l, None)),
            Detect::Partial => detector_partial = true,
            _ => {}
        }
        match (best, partial) {
            (_, Some(h)) => Hit::Partial {
                vault: true,
                handle: h,
            },
            _ if detector_partial => Hit::Partial {
                vault: false,
                handle: None,
            },
            (Some((l, h)), None) => Hit::Full(l, h),
            (None, None) => Hit::None,
        }
    }

    pub fn stream(&self) -> Stream<'_> {
        Stream {
            r: self,
            pending: Zeroizing::new(Vec::new()),
            hits: 0,
        }
    }

    /// One-shot redaction of a complete buffer (`Redact` requests, tests).
    pub fn redact_all(&self, data: &[u8]) -> (Vec<u8>, u64) {
        let mut s = self.stream();
        let mut out = Vec::with_capacity(data.len());
        s.push(data, &mut out);
        s.finish(&mut out);
        (out, s.hits)
    }
}

/// Per-stream state (one for stdout, one for stderr).
pub struct Stream<'r> {
    r: &'r Redactor,
    pending: Zeroizing<Vec<u8>>,
    pub hits: u64,
}

impl Stream<'_> {
    /// Append `data`; write every byte that can no longer be part of a match (redacted) to `out`.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) {
        self.reserve(data.len());
        self.pending.extend_from_slice(data);
        self.process(false, out);
    }

    /// EOF: release everything, redacting complete matches and secret-like held prefixes.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        self.process(true, out);
    }

    /// Grow `pending` without leaving the old allocation readable (it can hold partial secrets).
    fn reserve(&mut self, extra: usize) {
        let need = self.pending.len().saturating_add(extra);
        if need > self.pending.capacity() {
            let mut n = Vec::with_capacity(
                need.max(self.pending.capacity().saturating_mul(2))
                    .max(4096),
            );
            n.extend_from_slice(&self.pending);
            let _old = std::mem::replace(&mut self.pending, Zeroizing::new(n));
        }
    }

    fn process(&mut self, eof: bool, out: &mut Vec<u8>) {
        let buf = &self.pending;
        let mut i = 0usize;
        let mut run = 0usize;
        while i < buf.len() {
            // fast skip: a position needs the full matcher only if its 4-byte filter bit is set, it can start a generic
            // detector, or it is too close to the end to tell (the last 7 bytes)
            if let Some(rest) = buf.get(i..)
                && rest.len() >= MIN_PATTERN
            {
                let k = rest
                    .windows(MIN_PATTERN)
                    .position(|w| {
                        self.r.filter_hit(w)
                            || matches!(w.first_chunk::<2>(), Some(&[a, b]) if detect2(a, b))
                    })
                    .unwrap_or(rest.len().saturating_sub(MIN_PATTERN - 1));
                i = i.saturating_add(k);
                if i >= buf.len() {
                    break;
                }
            }
            match self.r.find(buf, i) {
                Hit::None => i = i.saturating_add(1),
                Hit::Full(l, h) => {
                    out.extend_from_slice(buf.get(run..i).unwrap_or_default());
                    out.extend_from_slice(&self.r.token(h));
                    self.hits = self.hits.saturating_add(1);
                    i = i.saturating_add(l);
                    run = i;
                }
                Hit::Partial { vault, handle: h } => {
                    if !eof {
                        break;
                    }
                    // EOF: a complete shorter match here still wins; otherwise redact a secret-like tail
                    let tail = buf.len().saturating_sub(i);
                    if let Some((l, hh)) = self.r.full_only(buf, i) {
                        out.extend_from_slice(buf.get(run..i).unwrap_or_default());
                        out.extend_from_slice(&self.r.token(hh));
                        self.hits = self.hits.saturating_add(1);
                        i = i.saturating_add(l);
                        run = i;
                    } else if vault
                        && tail >= EOF_PARTIAL_MIN
                        && !buf.get(i..).unwrap_or_default().starts_with(b"-----")
                        && crate::vault::strength::estimate_bits(buf.get(i..).unwrap_or_default())
                            >= EOF_PARTIAL_BITS
                    {
                        out.extend_from_slice(buf.get(run..i).unwrap_or_default());
                        out.extend_from_slice(&self.r.token(h));
                        self.hits = self.hits.saturating_add(1);
                        i = buf.len();
                        run = i;
                    } else {
                        i = i.saturating_add(1);
                    }
                }
            }
        }
        out.extend_from_slice(buf.get(run..i).unwrap_or_default());
        // keep the undecided tail; drop (and wipe, via the zero-on-free allocator) the rest
        let keep: Zeroizing<Vec<u8>> =
            Zeroizing::new(self.pending.get(i..).unwrap_or_default().to_vec());
        self.pending = keep;
    }
}

impl Redactor {
    /// Longest complete match at `i`, ignoring partials (EOF decisions).
    fn full_only(&self, buf: &[u8], i: usize) -> Option<(usize, Option<u32>)> {
        let rest = buf.get(i..)?;
        let mut best: Option<(usize, Option<u32>)> = None;
        if rest.len() >= MIN_PATTERN
            && let Some(c) = self.prefix8.get(&pack(rest.get(..8)?))
        {
            for &pi in c {
                let p = self.pats.get(usize::try_from(pi).ok()?)?;
                let pb = p.bytes.expose();
                if rest.get(..pb.len()) == Some(pb) && best.is_none_or(|(l, _)| pb.len() > l) {
                    best = Some((pb.len(), Some(p.handle)));
                }
            }
        }
        if let Detect::Full(l) = detect_eof(rest)
            && best.is_none_or(|(b, _)| l > b)
        {
            best = Some((l, None));
        }
        best
    }
}

// ---------------------------------------------------------------- generic detectors

enum Detect {
    None,
    Full(usize),
    Partial,
}

fn run_len(b: &[u8], ok: impl Fn(u8) -> bool) -> usize {
    b.iter().take_while(|&&c| ok(c)).count()
}

/// A detector match still growing at the end of the buffer is held back (`Partial`) — but never past `MAX_DETECT`:
/// beyond that the held run is redacted as one match and streaming resumes (fail closed; bounds memory and rescans).
fn held(b: &[u8]) -> Detect {
    if b.len() >= MAX_DETECT {
        Detect::Full(b.len())
    } else {
        Detect::Partial
    }
}

/// `prefix` then ≥ `min` chars of `class`; the token ends at the first byte outside `class`.
fn token_rule(
    b: &[u8],
    prefix: &[u8],
    min: usize,
    exact: bool,
    class: impl Fn(u8) -> bool,
) -> Detect {
    let n = prefix.len().min(b.len());
    if b.get(..n) != prefix.get(..n) {
        return Detect::None;
    }
    if b.len() < prefix.len() {
        return Detect::Partial;
    }
    let body = b.get(prefix.len()..).unwrap_or_default();
    let k = run_len(body, &class);
    let total = prefix.len().saturating_add(k);
    if k == body.len() {
        // ran into the end of the buffer: the token may continue
        return if exact && k >= min {
            Detect::Full(prefix.len().saturating_add(min))
        } else {
            held(b)
        };
    }
    if exact {
        return if k == min {
            Detect::Full(total)
        } else {
            Detect::None
        };
    }
    if k >= min {
        Detect::Full(total)
    } else {
        Detect::None
    }
}

fn alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// Generic detectors at the start of `b` (SPEC §5.8). `Partial` = could become a match with more input.
fn detect(b: &[u8]) -> Detect {
    let Some(&first) = b.first() else {
        return Detect::None;
    };
    let mut out = Detect::None;
    let mut consider = |d: Detect| {
        out = match (&out, d) {
            (Detect::Partial, _) | (_, Detect::Partial) => Detect::Partial,
            (Detect::Full(a), Detect::Full(c)) => Detect::Full((*a).max(c)),
            (Detect::Full(a), Detect::None) => Detect::Full(*a),
            (Detect::None, d) => d,
        }
    };
    match first {
        b'A' => {
            for p in [&b"AKIA"[..], b"ASIA"] {
                consider(token_rule(b, p, 16, true, |c| {
                    c.is_ascii_uppercase() || c.is_ascii_digit()
                }));
            }
        }
        b'g' => {
            for p in [&b"ghp_"[..], b"gho_", b"ghu_", b"ghs_", b"ghr_"] {
                consider(token_rule(b, p, 36, false, alnum));
            }
            consider(token_rule(b, b"github_pat_", 22, false, |c| {
                alnum(c) || c == b'_'
            }));
        }
        b's' | b'r' => {
            for p in [&b"sk_live_"[..], b"rk_live_", b"sk_test_", b"rk_test_"] {
                consider(token_rule(b, p, 16, false, alnum));
            }
        }
        b'x' => {
            for p in [&b"xoxb-"[..], b"xoxp-", b"xoxa-", b"xoxr-", b"xoxs-"] {
                consider(token_rule(b, p, 10, false, |c| alnum(c) || c == b'-'));
            }
        }
        b'e' => consider(jwt(b)),
        b'-' => consider(pem(b)),
        _ => {}
    }
    out
}

/// At EOF nothing can continue: a `Partial` with a complete shape still counts as a match where the rule allows.
fn detect_eof(b: &[u8]) -> Detect {
    let mut padded = b.to_vec();
    padded.push(b'\n');
    match detect(&padded) {
        Detect::Full(l) => Detect::Full(l.min(b.len())),
        _ => Detect::None,
    }
}

/// `eyJ<b64url ≥10>.eyJ<b64url ≥10>.<b64url ≥10>`
fn jwt(b: &[u8]) -> Detect {
    let mut i = 0usize;
    for (n, part) in [true, true, false].iter().enumerate() {
        let seg = b.get(i..).unwrap_or_default();
        if *part {
            let k = 3.min(seg.len());
            if seg.get(..k) != b"eyJ".get(..k) {
                return Detect::None;
            }
        }
        let k = run_len(seg, b64url);
        if k == seg.len() {
            return held(b);
        }
        if k < 10 {
            return Detect::None;
        }
        i = i.saturating_add(k);
        if n < 2 {
            match b.get(i) {
                Some(b'.') => i = i.saturating_add(1),
                _ => return Detect::None,
            }
        }
    }
    Detect::Full(i)
}

/// `-----BEGIN … PRIVATE KEY-----` … `-----END … PRIVATE KEY-----`, held up to 64 KiB.
fn pem(b: &[u8]) -> Detect {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let n = BEGIN.len().min(b.len());
    if b.get(..n) != BEGIN.get(..n) {
        return Detect::None;
    }
    let Some(line_end) = b.iter().position(|&c| c == b'\n') else {
        return if b.len() < 128 {
            Detect::Partial
        } else {
            Detect::None
        };
    };
    let first = b.get(..line_end).unwrap_or_default();
    if !first.windows(11).any(|w| w == b"PRIVATE KEY") {
        return Detect::None;
    }
    let hay = b.get(..b.len().min(MAX_DETECT)).unwrap_or_default();
    match hay.windows(9).position(|w| w == b"-----END ") {
        Some(p) => {
            let after = hay.get(p..).unwrap_or_default();
            match after.iter().skip(9).position(|&c| c == b'\n') {
                Some(e) => Detect::Full(p.saturating_add(9).saturating_add(e)),
                None if b.len() < MAX_DETECT => Detect::Partial,
                None => Detect::Full(b.len().min(MAX_DETECT)),
            }
        }
        None if b.len() < MAX_DETECT => Detect::Partial,
        // never released unredacted: an unterminated key block beyond the cap is redacted wholesale
        None => Detect::Full(MAX_DETECT),
    }
}

#[cfg(test)]
mod tests;
