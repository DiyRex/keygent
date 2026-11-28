//! Broker client (SPEC §5.4 "Clients verify the broker", ADR 0004). Every client, with or without auth:
//! 1. checks the runtime dir (`lstat`: owner, mode 0700, not a symlink) before connecting;
//! 2. checks the peer: same uid, and the peer PID + its start time match `broker.lock`, the lock is actually held, and
//!    the peer's executable has the same SHA-256 as this keygent binary;
//! 3. sends `Hello` and reads `Welcome`. Auth flows (which unwrapped the DEK locally) also verify the broker proof.
//!
//! Any verification failure fails closed with `BrokerUnverified`; "not running" maps to `Sealed` (exit 78).

use crate::broker::endpoint;
use crate::crypto;
use crate::error::{Error, Result};
use crate::platform::{Dirs, ipc};
use crate::proto::frame::{self, Frame, ty};
use crate::proto::msg::{self, Class, ErrMsg, Hello, Welcome, code};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Conn {
    s: UnixStream,
    pub nc: [u8; msg::NONCE_LEN],
    pub welcome: Welcome,
}

fn file_sha256(p: &Path) -> Result<[u8; 32]> {
    let f = std::fs::File::open(p)?;
    crypto::sha256_reader(f, 256 * 1024 * 1024)?.ok_or(Error::BrokerUnverified)
}

/// The peer must be the real broker: same uid, PID + start time recorded in a **held** `broker.lock`, and an
/// executable identical (by hash) to this binary. Residual: a same-user race between these checks is T3 (SPEC §5.4).
fn verify_peer(s: &UnixStream, run: &Path) -> Result<()> {
    let (uid, pid) = ipc::peer_cred(s).map_err(|_| Error::BrokerUnverified)?;
    if uid != ipc::uid() {
        return Err(Error::BrokerUnverified);
    }
    let (info, held) = endpoint::read_lock(run).map_err(|_| Error::BrokerUnverified)?;
    if !held || info.pid != pid {
        return Err(Error::BrokerUnverified);
    }
    if ipc::process_start(pid).map_err(|_| Error::BrokerUnverified)? != info.start {
        return Err(Error::BrokerUnverified);
    }
    let peer_exe = match ipc::process_exe(pid) {
        Ok(p) => p,
        // Linux: a non-dumpable broker's /proc/<pid>/exe is unreadable to same-user processes (ADR 0013). The lock,
        // PID and start-time checks above still hold; a squatter can only exist while no real broker runs.
        #[cfg(target_os = "linux")]
        Err(Error::Io(code)) if code == ipc::EACCES => return Ok(()),
        Err(_) => return Err(Error::BrokerUnverified),
    };
    if peer_exe != info.exe {
        return Err(Error::BrokerUnverified);
    }
    let me = std::env::current_exe().map_err(|_| Error::BrokerUnverified)?;
    if file_sha256(&peer_exe).map_err(|_| Error::BrokerUnverified)?
        != file_sha256(&me).map_err(|_| Error::BrokerUnverified)?
    {
        return Err(Error::BrokerUnverified);
    }
    Ok(())
}

/// A broker-relayed line must look like one of ours: `keygent:` prefix, ≤ 120 chars, no control characters.
fn relayed(exit: u8, m: String) -> Error {
    if m.starts_with("keygent: ") && m.chars().count() <= 120 && !m.chars().any(char::is_control) {
        Error::Remote(exit, m)
    } else {
        Error::BrokerUnverified
    }
}

pub fn err_from(f: &Frame) -> Error {
    use crate::error::exit;
    match ErrMsg::decode(&f.payload) {
        Ok(e) => match e.code {
            code::APPROVAL_DENIED => relayed(exit::APPROVAL, e.message),
            code::POLICY_DENIED => relayed(exit::POLICY, e.message),
            code::RUN_LIMIT => relayed(exit::RUN_LIMIT, e.message),
            code::NOT_TRUSTED => relayed(exit::NOT_TRUSTED, e.message),
            code::AUDIT => relayed(exit::BROKER, e.message),
            code::FAILED => relayed(exit::HUMAN, e.message),
            code::BAD_REQUEST
                if e.message.starts_with("keygent: usage")
                    || e.message.starts_with("keygent: can't parse")
                    || e.message.starts_with("keygent: --remember") =>
            {
                relayed(exit::USAGE, e.message)
            }
            code::SEALED => Error::Sealed,
            code::VERSION_MISMATCH => Error::VersionMismatch,
            code::RATE_LIMITED => Error::RateLimited,
            code::TOO_LARGE => Error::TooLarge("1 MiB"),
            code::NEEDS_AUTH => Error::NeedsAuth,
            c => Error::Broker(c),
        },
        Err(_) => Error::BrokerUnverified,
    }
}

pub fn connect(dirs: &Dirs, class: Class) -> Result<Conn> {
    match ipc::check_private_dir(&dirs.run) {
        Ok(()) => {}
        Err(Error::Io(_)) => return Err(Error::Sealed),
        Err(e) => return Err(e),
    }
    let sock = endpoint::socket_path(&dirs.run);
    let s = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Err(Error::Sealed);
        }
        Err(e) => return Err(e.into()),
    };
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
    verify_peer(&s, &dirs.run)?;
    let mut conn = Conn {
        s,
        nc: crypto::random()?,
        welcome: Welcome {
            build_id: String::new(),
            nonce: [0; 32],
            proof: [0; 32],
        },
    };
    let hello = Hello {
        build_id: super::build_id(),
        nonce: conn.nc,
        class,
    }
    .encode()
    .map_err(|_| Error::Internal(120))?;
    frame::write(&mut conn.s, ty::HELLO, &hello).map_err(|_| Error::Sealed)?;
    let f = frame::read(&mut conn.s).map_err(|_| Error::BrokerUnverified)?;
    match f.ty {
        ty::WELCOME => {}
        ty::ERR => return Err(err_from(&f)),
        _ => return Err(Error::BrokerUnverified),
    }
    conn.welcome = Welcome::decode(&f.payload).map_err(|_| Error::BrokerUnverified)?;
    if conn.welcome.build_id != super::build_id() {
        return Err(Error::VersionMismatch);
    }
    Ok(conn)
}

impl Conn {
    /// Auth flows: verify the broker's proof with locally derived keys (a squatting fake broker can't produce it).
    pub fn verify_broker(&self, expected: &[u8; 32]) -> Result<()> {
        if crypto::verify_proof(expected, &self.welcome.proof) {
            Ok(())
        } else {
            Err(Error::BrokerUnverified)
        }
    }

    /// Runs and approval waits can be quiet for a long time: no read timeout.
    pub fn no_read_timeout(&self) -> Result<()> {
        self.s.set_read_timeout(None)?;
        Ok(())
    }

    pub fn try_clone_stream(&self) -> Result<UnixStream> {
        Ok(self.s.try_clone()?)
    }

    /// Send one frame without reading a reply (`Run` streams its replies).
    pub fn send(&mut self, t: u8, payload: &[u8]) -> Result<()> {
        frame::write(&mut self.s, t, payload).map_err(|_| Error::Broker(0))
    }

    pub fn recv(&mut self) -> Result<Frame> {
        frame::read(&mut self.s).map_err(|_| Error::Broker(0))
    }

    /// Send one request and read one reply frame; `Err` frames become errors.
    pub fn request(&mut self, t: u8, payload: &[u8]) -> Result<Frame> {
        frame::write(&mut self.s, t, payload).map_err(|_| Error::Broker(0))?;
        let f = frame::read(&mut self.s).map_err(|_| Error::Broker(0))?;
        if f.ty == ty::ERR {
            return Err(err_from(&f));
        }
        Ok(f)
    }
}

/// Ask a running broker to seal and wait until its endpoint is gone (factor changes, ADR 0012).
pub fn seal_if_running(dirs: &Dirs) -> Result<bool> {
    let mut c = match connect(dirs, Class::Control) {
        Ok(c) => c,
        Err(Error::Sealed) => return Ok(false),
        Err(e) => return Err(e),
    };
    c.request(ty::SEAL, &[])?;
    let sock = endpoint::socket_path(&dirs.run);
    for _ in 0..100 {
        if !sock.exists() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(Error::Broker(code::INTERNAL))
}
