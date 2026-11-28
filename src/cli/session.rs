//! `unseal`, `seal`, `status`, `ls` (SPEC §5.1, §5.4).
//!
//! `unseal` reads the passphrase on the terminal, opens the vault locally, starts `keygent broker` with a cleared env
//! and one pipe, hands over the DEK, then verifies the new broker's handshake proof with keys derived locally — so a
//! squatting fake broker is detected before `unseal` reports success. The DEK is wiped on every path.

use super::Args;
use super::client::{self, Conn};
use super::console::Console;
use crate::broker::{self, Handoff};
use crate::crypto::Dek;
use crate::error::{Error, Result};
use crate::platform::{self, Dirs, ipc};
use crate::proto::frame::ty;
use crate::proto::msg::{self, Class, StatusReply};
use crate::vault::index::Mode;
use crate::vault::{self, Vault};
use std::io::Write;
use std::time::Duration;

const START_WAIT: Duration = Duration::from_secs(10);

/// `30s`, `45m`, `8h` → Duration (≤ 24 h).
pub(super) fn parse_duration(s: &str) -> Option<Duration> {
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    (secs > 0 && secs <= 24 * 3600).then(|| Duration::from_secs(secs))
}

fn fmt_dur(secs: u64) -> String {
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

fn say_err(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

pub fn unseal(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent unseal [--ttl 8h] [--log info|debug]"));
    }
    let req_ttl = match a.value("--ttl") {
        Some(t) => Some(parse_duration(t).ok_or(Error::Usage("--ttl: e.g. 30m, 8h (max 24h)"))?),
        None => None,
    };
    let log_level = match a.value("--log") {
        None | Some("info") => 2,
        Some("debug") => 3,
        Some(_) => return Err(Error::Usage("--log info|debug")),
    };
    let d = platform::dirs()?;
    match client::connect(&d, Class::Control) {
        Ok(_) => {
            say_err("keygent: already unsealed");
            return Ok(());
        }
        Err(Error::Sealed) => {}
        Err(e) => return Err(e),
    }
    let l = vault::lock(&d)?;
    let mut con = Console::open()?;
    let v = super::cmds::unlock_vault(&mut con, &d, &l)?;
    let sec = v.index.security;
    let ttl = req_ttl
        .unwrap_or(broker::DEFAULT_TTL)
        .min(Duration::from_secs(u64::from(sec.ttl_max_secs)));
    let idle = Duration::from_secs(u64::from(sec.idle_secs));
    let dek = v.dek_copy();
    let uuid = v.file.uuid;
    drop(v);
    drop(l);
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_owned());
    let handoff = Handoff {
        dek: Dek::from_bytes(*dek.expose()),
        ttl,
        idle,
        log_level,
        path,
    };
    let bytes = handoff.encode()?;
    drop(handoff);
    let exe = std::env::current_exe()?;
    let mut child = ipc::spawn_broker(&exe)?;
    {
        let mut pipe = child.stdin.take().ok_or(Error::Internal(130))?;
        pipe.write_all(&bytes)?;
    }
    drop(bytes);
    // the broker daemonizes into its own session; reap our direct child handle without waiting on it
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    let conn = wait_for_broker(&d)?;
    let expected = broker::expected_proof(&dek, &uuid, &conn.nc, &conn.welcome.nonce)?;
    drop(dek);
    conn.verify_broker(&expected)?;
    con.say(&format!(
        "keygent: unsealed for {} (seals after {} idle)",
        fmt_dur(ttl.as_secs()),
        fmt_dur(idle.as_secs())
    ));
    Ok(())
}

fn wait_for_broker(d: &Dirs) -> Result<Conn> {
    let start = std::time::Instant::now();
    loop {
        match client::connect(d, Class::Control) {
            Ok(c) => return Ok(c),
            Err(Error::Sealed) if start.elapsed() < START_WAIT => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(Error::Sealed) => return Err(Error::Broker(msg::code::INTERNAL)),
            Err(e) => return Err(e),
        }
    }
}

pub fn seal(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent seal"));
    }
    let d = platform::dirs()?;
    if client::seal_if_running(&d)? {
        say_err("keygent: sealed");
    } else {
        say_err("keygent: already sealed");
    }
    Ok(())
}

pub fn status(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent status"));
    }
    let d = platform::dirs()?;
    let line = match client::connect(&d, Class::Control) {
        Ok(mut c) => {
            let f = c.request(ty::STATUS, &[])?;
            let s = StatusReply::decode(&f.payload).map_err(|_| Error::BrokerUnverified)?;
            format!(
                "keygent: unsealed — {} left, seals after {} idle, {} secret(s), hardening {}",
                fmt_dur(s.ttl_left_secs),
                fmt_dur(s.idle_left_secs),
                s.handles,
                if s.no_dumps { "on" } else { "PARTIAL" }
            )
        }
        Err(Error::Sealed) if Vault::exists(&d) => "keygent: vault sealed".to_owned(),
        Err(Error::Sealed) => "keygent: no vault — run 'keygent init'".to_owned(),
        Err(e) => return Err(e),
    };
    let _ = writeln!(std::io::stdout(), "{line}");
    Ok(())
}

/// Agent-safe listing: handles and metadata only (SPEC §5.1). Sealed → exit 78.
/// `audit [--since 1h] [--verify]` (agent-safe): print records (they hold templates, never values) or verify the
/// chain through the broker, which holds `K_audit`.
pub fn audit(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent audit [--since 1h] [--verify]"));
    }
    let d = platform::dirs()?;
    if a.has("--verify") {
        let mut c = client::connect(&d, Class::Run)?;
        let f = c.request(ty::AUDIT_VERIFY, &[])?;
        if f.ty != ty::AUDIT_OK {
            return Err(Error::BrokerUnverified);
        }
        let n = msg::decode_u32(&f.payload, crate::proto::tags::proto::COUNT)
            .map_err(|_| Error::BrokerUnverified)?;
        say_err(&format!("keygent: audit log intact ({n} records)"));
        return Ok(());
    }
    let since = match a.value("--since") {
        Some(v) => Some(parse_duration(v).ok_or(Error::Usage("--since: e.g. 30m, 2h, 24h"))?),
        None => None,
    };
    let cutoff = since.map(|s| vault::audit::rfc3339(vault::now().saturating_sub(s.as_secs())));
    let text = match std::fs::read_to_string(vault::audit::log_path(&d)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let mut out = std::io::stdout().lock();
    for line in text.lines() {
        let ts = line
            .split_once("\"ts\":\"")
            .and_then(|(_, r)| r.get(..20))
            .unwrap_or_default();
        if cutoff.as_deref().is_none_or(|c| ts >= c) {
            let _ = writeln!(out, "{line}");
        }
    }
    Ok(())
}

pub fn ls(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent ls"));
    }
    let d = platform::dirs()?;
    let mut c = client::connect(&d, Class::Run)?;
    let f = c.request(ty::LIST, &[])?;
    let entries = msg::decode_list(&f.payload).map_err(|_| Error::BrokerUnverified)?;
    let mut out = String::new();
    for e in entries {
        let mode = match e.mode {
            0 => Mode::Allow,
            1 => Mode::Confirm,
            3 => Mode::Deny,
            _ => Mode::Approve,
        };
        let mut line = format!("{}  ${}  {}", e.handle, e.env_name, mode.name());
        if e.binding == 1 {
            line.push_str("  file");
        } else if e.custody {
            line.push_str("  custody");
        }
        if e.exposed {
            line.push_str("  EXPOSED — rotate it");
        }
        // the human's description lets an agent pick the handle from plain words ("my DO token"); metadata only
        if !e.description.is_empty() {
            line.push_str("  — ");
            line.push_str(&e.description);
        }
        out.push_str(&line);
        out.push('\n');
    }
    let _ = std::io::stdout().write_all(out.as_bytes());
    Ok(())
}

/// Test-profile only: pipe stdin through the broker's `Redact` (exercises the real broker path in tests).
#[cfg(feature = "test-profile")]
pub fn test_redact() -> Result<()> {
    use std::io::Read;
    let mut data = Vec::new();
    std::io::stdin().take(512 * 1024).read_to_end(&mut data)?;
    let d = platform::dirs()?;
    let mut c = client::connect(&d, Class::Hook)?;
    let payload = msg::encode_data(&data, None).map_err(|_| Error::TooLarge("1 MiB"))?;
    let f = c.request(ty::REDACT, &payload)?;
    let (out, _) = msg::decode_data(&f.payload, true).map_err(|_| Error::BrokerUnverified)?;
    let _ = std::io::stdout().write_all(&out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("8h"), Some(Duration::from_secs(8 * 3600)));
        assert_eq!(parse_duration("24h"), Some(Duration::from_secs(24 * 3600)));
        for bad in ["25h", "0m", "h", "", "5d", "-1h", "1.5h"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        assert_eq!(fmt_dur(3600 * 7 + 59 * 60), "7h59m");
    }
}
