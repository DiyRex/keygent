//! Audit log (SPEC §9, FORMATS §5): `state/audit.jsonl`, owner-only, one JSON object per line, HMAC-chained with
//! `K_audit`, plus an append-only `state/audit.anchor` written after every record.
//!
//! - `mac = HMAC(K_audit, enc(prev_mac) ‖ enc(L))` where `L` is the line as written minus the trailing `,"mac":"…"`
//!   member (the writer always puts `mac` last). The first record chains from 32 zero bytes. MACs are lower-case hex.
//! - Anchor line: `<seq> <hex HMAC(K_audit, enc(seq as 8 LE bytes) ‖ enc(mac))>`.
//! - Writers (broker and CLI) take an exclusive lock on the log for read-tail + append + anchor.
//! - Records never hold values: `cmd` is the template with placeholders, and callers pass it through the redactor.
//!
//! Known gaps (documented): rotation (10 MB × 5), the 10-min tripwire anchor and the `rekey` epoch record.

use crate::crypto::{self, Subkey};
use crate::error::{Error, Result};
use crate::platform::{Dirs, ipc};
use std::fmt::Write as _;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const LOG: &str = "audit.jsonl";
pub const ANCHOR: &str = "audit.anchor";
/// One record line is bounded (commands are ≤ 64 KiB, escaped ≤ 6×).
const MAX_LINE: u64 = 512 * 1024;

/// One audit event. Empty / `None` fields are omitted from the line.
#[derive(Default)]
pub struct Record<'a> {
    pub event: &'a str,
    pub handles: Vec<String>,
    pub decision: Option<&'a str>,
    pub channel: Option<&'a str>,
    /// Command template (placeholders, never values), already redacted.
    pub cmd: Option<String>,
    pub grant_key: Option<[u8; 32]>,
    pub exes: Vec<(String, [u8; 32])>,
    pub scripts: Vec<(String, [u8; 32], u64)>,
    pub cwd: Option<String>,
    pub exit: Option<i32>,
    pub redactions: Option<u64>,
    pub dur_ms: Option<u64>,
}

impl<'a> Record<'a> {
    pub fn new(event: &'a str) -> Self {
        Record {
            event,
            ..Record::default()
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *o = u8::from_str_radix(s.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

/// JSON string literal (escapes `"`, `\` and every control character).
fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len().saturating_add(2));
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                let _ = write!(o, "\\u{:04x}", u32::from(c));
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// RFC 3339 UTC from Unix seconds (civil-from-days, H. Hinnant).
// days ≤ u64::MAX / 86 400 ≈ 2.1e14, so every intermediate below stays far inside i64.
#[allow(clippy::arithmetic_side_effects)]
pub fn rfc3339(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The line body (everything before `,"mac":…`), without the closing brace.
fn body(seq: u64, ts: u64, r: &Record<'_>) -> String {
    let mut o = format!(
        "{{\"v\":1,\"seq\":{seq},\"ts\":{},\"event\":{}",
        js(&rfc3339(ts)),
        js(r.event)
    );
    if !r.handles.is_empty() {
        let hs: Vec<String> = r.handles.iter().map(|h| js(h)).collect();
        let _ = write!(o, ",\"handles\":[{}]", hs.join(","));
    }
    if let Some(d) = r.decision {
        let _ = write!(o, ",\"decision\":{}", js(d));
    }
    if let Some(c) = r.channel {
        let _ = write!(o, ",\"channel\":{}", js(c));
    }
    if let Some(c) = &r.cmd {
        let _ = write!(o, ",\"cmd\":{}", js(c));
    }
    if let Some(k) = &r.grant_key {
        let _ = write!(o, ",\"grant_key\":{}", js(&hex(k)));
    }
    if !r.exes.is_empty() {
        let xs: Vec<String> = r
            .exes
            .iter()
            .map(|(p, h)| format!("{{\"path\":{},\"sha256\":{}}}", js(p), js(&hex(h))))
            .collect();
        let _ = write!(o, ",\"exes\":[{}]", xs.join(","));
    }
    if !r.scripts.is_empty() {
        let xs: Vec<String> = r
            .scripts
            .iter()
            .map(|(p, h, n)| {
                format!(
                    "{{\"path\":{},\"sha256\":{},\"size\":{n}}}",
                    js(p),
                    js(&hex(h))
                )
            })
            .collect();
        let _ = write!(o, ",\"scripts\":[{}]", xs.join(","));
    }
    if let Some(c) = &r.cwd {
        let _ = write!(o, ",\"cwd\":{}", js(c));
    }
    if let Some(e) = r.exit {
        let _ = write!(o, ",\"exit\":{e}");
    }
    if let Some(n) = r.redactions {
        let _ = write!(o, ",\"redactions\":{n}");
    }
    if let Some(n) = r.dur_ms {
        let _ = write!(o, ",\"dur_ms\":{n}");
    }
    o
}

fn chain_mac(key: &Subkey, prev: &[u8; 32], l: &[u8]) -> Result<[u8; 32]> {
    crypto::hmac(key, &crypto::enc(&[prev, l])?)
}

fn anchor_mac(key: &Subkey, seq: u64, mac: &[u8; 32]) -> Result<[u8; 32]> {
    crypto::hmac(key, &crypto::enc(&[&seq.to_le_bytes(), mac])?)
}

/// Split a written line into (`L` = the MAC input, seq, mac). `None` if it isn't one of ours.
fn parse_line(line: &str) -> Option<(String, u64, [u8; 32])> {
    let rest = line.strip_prefix("{\"v\":1,\"seq\":")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    let seq = digits.parse().ok()?;
    let at = line.rfind(",\"mac\":\"")?;
    let tail = line.get(at..)?;
    let mac_hex = tail.strip_prefix(",\"mac\":\"")?.strip_suffix("\"}")?;
    let mac = unhex32(mac_hex)?;
    let mut l = line.get(..at)?.to_owned();
    l.push('}');
    Some((l, seq, mac))
}

pub fn log_path(dirs: &Dirs) -> PathBuf {
    dirs.state.join(LOG)
}

/// Last complete line of the log (scans backwards; bounded by `MAX_LINE`).
fn last_line(f: &mut std::fs::File) -> Result<Option<String>> {
    let len = f.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }
    let take = len.min(MAX_LINE.saturating_add(1));
    f.seek(SeekFrom::Start(len.saturating_sub(take)))?;
    let mut buf = Vec::with_capacity(usize::try_from(take).unwrap_or(0));
    f.take(take).read_to_end(&mut buf)?;
    // a torn final write (no trailing newline) means the log was damaged
    if buf.last() != Some(&b'\n') {
        return Err(Error::Damaged);
    }
    buf.pop();
    let start = buf
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i.saturating_add(1));
    if start == 0 && len > take {
        return Err(Error::Damaged);
    }
    let line = String::from_utf8(buf.get(start..).unwrap_or_default().to_vec())
        .map_err(|_| Error::Damaged)?;
    Ok(Some(line))
}

fn open_append(p: &Path) -> Result<std::fs::File> {
    ipc::open_private_rw(p, true)
}

/// Append one record and its anchor. Returns the new (seq, mac). Any failure is an error the caller must treat as
/// fail-closed (runs refuse, vault writes don't happen).
pub fn append(dirs: &Dirs, key: &Subkey, r: &Record<'_>) -> Result<(u64, [u8; 32])> {
    let mut f = open_append(&log_path(dirs)).map_err(|_| Error::AuditUnwritable)?;
    f.lock().map_err(|_| Error::AuditUnwritable)?;
    let (seq, prev) = match last_line(&mut f).map_err(|_| Error::AuditUnwritable)? {
        None => (1, [0u8; 32]),
        Some(l) => {
            let (_, s, m) = parse_line(&l).ok_or(Error::AuditUnwritable)?;
            (s.checked_add(1).ok_or(Error::AuditUnwritable)?, m)
        }
    };
    let mut l = body(seq, super::now(), r);
    l.push('}');
    let mac = chain_mac(key, &prev, l.as_bytes())?;
    l.pop();
    let line = format!("{l},\"mac\":\"{}\"}}\n", hex(&mac));
    f.write_all(line.as_bytes())
        .and_then(|()| f.sync_data())
        .map_err(|_| Error::AuditUnwritable)?;
    let a = anchor_mac(key, seq, &mac)?;
    let mut af = open_append(&dirs.state.join(ANCHOR)).map_err(|_| Error::AuditUnwritable)?;
    af.write_all(format!("{seq} {}\n", hex(&a)).as_bytes())
        .and_then(|()| af.sync_data())
        .map_err(|_| Error::AuditUnwritable)?;
    Ok((seq, mac))
}

/// Verify the whole chain, the anchor file's last entry and (if given) the index anchor. Returns the record count, or
/// `Err(seq)` of the first record that fails (0 = the anchor or the file itself).
pub fn verify(
    dirs: &Dirs,
    key: &Subkey,
    index_anchor: Option<(u64, [u8; 32])>,
) -> std::result::Result<u64, u64> {
    let text = match std::fs::read(log_path(dirs)) {
        Ok(b) => String::from_utf8(b).map_err(|_| 0u64)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err(0),
    };
    let mut prev = [0u8; 32];
    let mut expect = 1u64;
    let mut index_seen = index_anchor.is_none();
    for line in text.lines() {
        let (l, seq, mac) = parse_line(line).ok_or(expect)?;
        if seq != expect {
            return Err(expect);
        }
        let want = chain_mac(key, &prev, l.as_bytes()).map_err(|_| seq)?;
        if !crypto::ct_eq(&want, &mac) {
            return Err(seq);
        }
        if let Some((s, m)) = index_anchor
            && s == seq
        {
            if !crypto::ct_eq(&m, &mac) {
                return Err(seq);
            }
            index_seen = true;
        }
        prev = mac;
        expect = expect.saturating_add(1);
    }
    let count = expect.saturating_sub(1);
    if !index_seen {
        // the log was truncated below what the vault last anchored
        return Err(0);
    }
    // the last anchor must name the last record
    let anchors = std::fs::read_to_string(dirs.state.join(ANCHOR)).unwrap_or_default();
    match anchors.lines().last() {
        None if count == 0 => Ok(0),
        None => Err(0),
        Some(a) => {
            let (s, h) = a.split_once(' ').ok_or(0u64)?;
            let s: u64 = s.parse().map_err(|_| 0u64)?;
            let h = unhex32(h).ok_or(0u64)?;
            let want = anchor_mac(key, s, &prev).map_err(|_| 0u64)?;
            if s == count && crypto::ct_eq(&want, &h) {
                Ok(count)
            } else {
                Err(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn dirs() -> Dirs {
        let r = std::env::temp_dir().join(format!(
            "kg-audit-{}",
            hex(&crate::crypto::random::<6>().unwrap())
        ));
        let d = Dirs {
            data: r.join("data"),
            config: r.join("config"),
            state: r.join("state"),
            run: r.join("run"),
        };
        std::fs::create_dir_all(&d.state).unwrap();
        d
    }

    #[test]
    fn chain_appends_verifies_and_detects_tampering() {
        let d = dirs();
        let k = Subkey::from_bytes([7; 32]);
        let mut r = Record::new("run");
        r.handles = vec!["svc/key".into()];
        r.cmd = Some("X={{keygent:svc/key}} t \"q\"\n".into());
        r.exit = Some(0);
        assert_eq!(append(&d, &k, &r).unwrap().0, 1);
        let (seq, mac) = append(&d, &k, &Record::new("deny")).unwrap();
        assert_eq!(seq, 2);
        assert_eq!(verify(&d, &k, Some((2, mac))), Ok(2));
        assert_eq!(
            verify(&d, &Subkey::from_bytes([8; 32]), None),
            Err(1),
            "wrong key"
        );
        // one line per record, mac last, newline escaped
        let text = std::fs::read_to_string(log_path(&d)).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("\\\"q\\\"\\n"));
        // edit a record → that seq fails
        std::fs::write(log_path(&d), text.replacen("\"exit\":0", "\"exit\":1", 1)).unwrap();
        assert_eq!(verify(&d, &k, None), Err(1));
        // truncation below the index anchor is caught
        std::fs::write(log_path(&d), text.lines().next().unwrap().to_owned() + "\n").unwrap();
        assert_eq!(verify(&d, &k, Some((2, mac))), Err(0));
        assert_eq!(verify(&d, &k, None), Err(0), "anchor names a later record");
        let _ = std::fs::remove_dir_all(d.state.parent().unwrap());
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_794_478_323), "2026-11-12T10:12:03Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
