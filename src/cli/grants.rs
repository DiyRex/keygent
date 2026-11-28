//! `run`, `pending`, `approve`, `deny` (SPEC §5.5.2, §5.7).
//!
//! - `run` is a thin client: it never sees values. Direct use sends `{cmd, cwd}` and the broker creates the grant;
//!   `--grant <id>` sends only the id. It waits for approval, then streams the broker's redacted output and exits
//!   with the child's code. Interrupts are forwarded to the run's process group.
//! - `approve` shows the broker-rendered request in full, asks for the passphrase, verifies the broker, and sends
//!   `Approve{id, key}` with `proof_c` over exactly that id and key.

use super::Args;
use super::client::{self, Conn};
use super::console::Console;
use crate::crypto::hex;
use crate::error::{Error, PolicyMsg, Result};
use crate::platform::{self, ipc};
use crate::proto::frame::ty;
use crate::proto::msg::{self, Approve, Class, GRANT_ID_LEN, GrantCreate, PendingGrant, gstate};
use crate::proto::tags::proto as t;
use crate::vault;
use std::io::Write;

fn parse_id(s: &str) -> Result<[u8; GRANT_ID_LEN]> {
    let usage = Error::Usage("keygent run --grant <32 hex chars>");
    if s.len() != GRANT_ID_LEN.saturating_mul(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(usage);
    }
    let mut id = [0u8; GRANT_ID_LEN];
    for (i, out) in id.iter_mut().enumerate() {
        let at = i.saturating_mul(2);
        *out = s
            .get(at..at.saturating_add(2))
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .ok_or(Error::Usage("keygent run --grant <32 hex chars>"))?;
    }
    Ok(id)
}

const WAITING: &str = "keygent: waiting for approval — ask the user to run 'keygent approve'";

/// `capture <handle> -- '<command>'` (SPEC §5.9): like `run`, but the broker stores stdout (trimmed) as a new handle
/// and never returns it. Agent-safe: it can only create.
pub fn capture(a: Args) -> Result<()> {
    let Some((h, cmd)) = a.pos.split_first() else {
        return Err(Error::Usage("keygent capture <handle> -- '<command>'"));
    };
    crate::vault::names::check_handle(h)?;
    if cmd.is_empty() {
        return Err(Error::Usage("keygent capture <handle> -- '<command>'"));
    }
    run_inner(&a, cmd, Some(h))?;
    let _ = writeln!(
        std::io::stderr(),
        "keygent: stored {h} (env {}, mode approve)",
        crate::vault::names::placeholder_env(h)
    );
    Ok(())
}

pub fn run(a: Args) -> Result<()> {
    run_inner(&a, &a.pos, None)
}

fn run_inner(a: &Args, words: &[String], capture: Option<&String>) -> Result<()> {
    if a.value("--dialect").is_some_and(|d| d != "posix") {
        return Err(Error::Unsupported("--dialect other than posix"));
    }
    let d = platform::dirs()?;
    let id = match a.value("--grant") {
        Some(g) => {
            if !a.pos.is_empty() || a.has("--max-runtime") {
                return Err(Error::Usage("keygent run --grant <id> takes no command"));
            }
            parse_id(g)?
        }
        None => {
            if words.is_empty() {
                return Err(Error::Usage(
                    "keygent run [--max-runtime 30m] -- '<command>'",
                ));
            }
            let max_runtime_secs = match a.value("--max-runtime") {
                Some(v) => Some(
                    super::session::parse_duration(v)
                        .ok_or(Error::Usage("--max-runtime: e.g. 45m, 2h (max 4h)"))?
                        .as_secs(),
                ),
                None => None,
            };
            let cwd = std::env::current_dir()?;
            let req = GrantCreate {
                cmd: words.join(" "),
                cwd: cwd
                    .to_str()
                    .ok_or(Error::Policy(PolicyMsg::BadCwd))?
                    .to_owned(),
                max_runtime_secs,
                capture: capture.cloned(),
            }
            .encode()
            .map_err(|_| Error::TooLarge("64 KiB command"))?;
            let mut c = client::connect(&d, Class::Run)?;
            let f = c.request(ty::GRANT_CREATE, &req)?;
            if f.ty != ty::GRANT_CREATED {
                return Err(Error::BrokerUnverified);
            }
            let (id, state) =
                msg::decode_grant(&f.payload, true).map_err(|_| Error::BrokerUnverified)?;
            if state == gstate::PENDING {
                let _ = writeln!(std::io::stderr(), "{WAITING}");
            }
            id
        }
    };
    // wait for the decision (returns at once when already approved)
    let mut c = client::connect(&d, Class::Run)?;
    c.no_read_timeout()?;
    let p = msg::encode_grant(&id, None).map_err(|_| Error::Internal(150))?;
    let f = c.request(ty::AWAIT_GRANT, &p)?;
    if f.ty != ty::GRANT_DECISION {
        return Err(Error::BrokerUnverified);
    }
    drop(c);
    stream(&d, &id)
}

/// `Run{id}`: copy STDOUT/STDERR frames out, forward interrupts, exit with the child's code.
fn stream(d: &platform::Dirs, id: &[u8; GRANT_ID_LEN]) -> Result<()> {
    let mut c = client::connect(d, Class::Run)?;
    c.no_read_timeout()?;
    // from here on SIGINT/SIGTERM/SIGHUP are forwarded to the run instead of killing this client
    ipc::block_term_signals();
    let mut sig_out = c.try_clone_stream()?;
    let _ = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            loop {
                let n = ipc::wait_term_signal();
                let Ok(p) = msg::encode_u32(t::SIGNAL, u32::try_from(n).unwrap_or(0)) else {
                    return;
                };
                if crate::proto::frame::write(&mut sig_out, ty::SIGNAL, &p).is_err() {
                    return;
                }
            }
        });
    c.send(
        ty::RUN,
        &msg::encode_grant(id, None).map_err(|_| Error::Internal(151))?,
    )?;
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr();
    loop {
        let f = c.recv().map_err(|_| Error::Broker(msg::code::INTERNAL))?;
        match f.ty {
            ty::STDOUT | ty::STDERR => {
                let (data, _) =
                    msg::decode_data(&f.payload, false).map_err(|_| Error::BrokerUnverified)?;
                let w: &mut dyn Write = if f.ty == ty::STDOUT {
                    &mut out
                } else {
                    &mut err
                };
                // a closed stdout (`| head`) must not stop the run's own handling; ignore write errors
                let _ = w.write_all(&data).and_then(|()| w.flush());
            }
            ty::EXIT => {
                let code = msg::decode_u32(&f.payload, t::EXIT_CODE)
                    .map_err(|_| Error::BrokerUnverified)?;
                return match u8::try_from(code).unwrap_or(1) {
                    0 => Ok(()),
                    n => Err(Error::Exit(n)),
                };
            }
            ty::ERR => return Err(client::err_from(&f)),
            _ => return Err(Error::BrokerUnverified),
        }
    }
}

fn fetch_pending(d: &platform::Dirs) -> Result<Vec<PendingGrant>> {
    let mut c = client::connect(d, Class::Auth)?;
    let f = c.request(ty::PENDING, &[])?;
    if f.ty != ty::PENDING_REPLY {
        return Err(Error::BrokerUnverified);
    }
    msg::decode_pending(&f.payload).map_err(|_| Error::BrokerUnverified)
}

/// Pick by id prefix (≥ 4 hex chars, unique), or the only pending request. No batch approve (SPEC §5.5.2).
fn select(list: Vec<PendingGrant>, id: Option<&str>) -> Result<PendingGrant> {
    let mut hits: Vec<PendingGrant> = match id {
        Some(p) => {
            let p = p.to_ascii_lowercase();
            if p.len() < 4 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Usage(
                    "an id from 'keygent pending' (at least 4 hex chars)",
                ));
            }
            list.into_iter()
                .filter(|g| hex(&g.id).starts_with(&p))
                .collect()
        }
        None => list,
    };
    match hits.len() {
        0 => Err(Error::NoPending),
        1 => hits.pop().ok_or(Error::NoPending),
        _ => Err(Error::AmbiguousPending),
    }
}

pub fn pending(a: Args) -> Result<()> {
    if !a.pos.is_empty() {
        return Err(Error::Usage("keygent pending"));
    }
    let list = fetch_pending(&platform::dirs()?)?;
    let mut o = std::io::stdout().lock();
    if list.is_empty() {
        let _ = writeln!(o, "no pending requests");
    }
    for g in &list {
        let _ = writeln!(o, "request {}\n{}", hex(&g.id), g.rendered);
    }
    Ok(())
}

pub fn approve(a: Args) -> Result<()> {
    if a.pos.len() > 1 {
        return Err(Error::Usage("keygent approve [<id>] [--remember]"));
    }
    let d = platform::dirs()?;
    let mut con = Console::open()?;
    let g = select(fetch_pending(&d)?, a.pos.first().map(String::as_str))?;
    let remember = a.has("--remember");
    if remember && g.unbound {
        return Err(Error::Policy(PolicyMsg::NoRemember));
    }
    // the full rendered request (every bound script included) comes before the passphrase prompt
    con.say(&format!("request {}", hex(&g.id)));
    con.say(&g.rendered);
    let v = {
        let l = vault::lock(&d)?;
        super::cmds::unlock_vault(&mut con, &d, &l)?
    };
    let mut c: Conn = client::connect(&d, Class::Auth)?;
    c.verify_broker(&v.broker_proof(&c.nc, &c.welcome.nonce)?)?;
    let mut ap = Approve {
        id: g.id,
        key: g.key,
        remember,
        proof: [0; 32],
    };
    let req = ap.request_bytes().map_err(|_| Error::Internal(152))?;
    ap.proof = v.auth_proof(&c.welcome.nonce, &c.nc, &req)?;
    drop(v);
    let f = c.request(ty::APPROVE, &ap.encode().map_err(|_| Error::Internal(153))?)?;
    if f.ty != ty::OK {
        return Err(Error::BrokerUnverified);
    }
    con.say("keygent: approved");
    Ok(())
}

pub fn deny(a: Args) -> Result<()> {
    let d = platform::dirs()?;
    let p = if a.has("--all") {
        if !a.pos.is_empty() {
            return Err(Error::Usage("keygent deny [<id> | --all]"));
        }
        msg::encode_deny(None)
    } else {
        if a.pos.len() > 1 {
            return Err(Error::Usage("keygent deny [<id> | --all]"));
        }
        let g = select(fetch_pending(&d)?, a.pos.first().map(String::as_str))?;
        msg::encode_deny(Some(&g.id))
    }
    .map_err(|_| Error::Internal(154))?;
    let mut c = client::connect(&d, Class::Control)?;
    let f = c.request(ty::DENY, &p)?;
    if f.ty != ty::OK {
        return Err(Error::BrokerUnverified);
    }
    let _ = writeln!(std::io::stderr(), "keygent: denied");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: a panic is the failure report")]
    use super::*;

    fn pg(b: u8) -> PendingGrant {
        PendingGrant {
            id: [b; 16],
            key: [0; 32],
            unbound: true,
            rendered: String::new(),
        }
    }

    #[test]
    fn ids_and_selection() {
        assert_eq!(parse_id(&"ab".repeat(16)).unwrap(), [0xab; 16]);
        assert!(parse_id("abc").is_err());
        assert!(parse_id(&"zz".repeat(16)).is_err());
        assert_eq!(select(vec![pg(1)], None).unwrap().id, [1; 16]);
        assert_eq!(
            select(vec![pg(1), pg(2)], None).unwrap_err(),
            Error::AmbiguousPending
        );
        assert_eq!(
            select(vec![pg(1), pg(2)], Some("0202")).unwrap().id,
            [2; 16]
        );
        assert_eq!(select(vec![], None).unwrap_err(), Error::NoPending);
        assert!(
            select(vec![pg(1)], Some("01")).is_err(),
            "too short a prefix"
        );
    }
}
