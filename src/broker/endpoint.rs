//! Broker endpoint (SPEC §5.4, PLATFORMS "Exclusive bind"): fixed per-user runtime dir, `broker.lock` held for the
//! broker's lifetime and holding `{pid, start time, exe}`, and stale-socket recovery (lock free → unlink → rebind).

use crate::error::{Error, Result};
use crate::platform::{self, Platform, ipc};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

pub const SOCK: &str = "broker.sock";
pub const LOCK: &str = "broker.lock";

pub fn socket_path(run: &Path) -> PathBuf {
    run.join(SOCK)
}

/// Contents of `broker.lock`: `v1 <pid> <start> <exe path>`.
#[derive(Debug, PartialEq, Eq)]
pub struct LockInfo {
    pub pid: i32,
    pub start: u64,
    pub exe: PathBuf,
}

impl LockInfo {
    pub fn render(&self) -> String {
        format!("v1 {} {} {}\n", self.pid, self.start, self.exe.display())
    }

    pub fn parse(s: &str) -> Option<LockInfo> {
        let line = s.strip_suffix('\n')?;
        let rest = line.strip_prefix("v1 ")?;
        let (pid, rest) = rest.split_once(' ')?;
        let (start, exe) = rest.split_once(' ')?;
        let exe = PathBuf::from(exe);
        exe.is_absolute().then_some(())?;
        Some(LockInfo {
            pid: pid.parse().ok()?,
            start: start.parse().ok()?,
            exe,
        })
    }
}

/// Read `broker.lock` and report whether it is currently held (client side).
pub fn read_lock(run: &Path) -> Result<(LockInfo, bool)> {
    let f = platform::os()
        .open_private(&run.join(LOCK))?
        .ok_or(Error::Sealed)?;
    let mut s = String::new();
    (&f).take(4096)
        .read_to_string(&mut s)
        .map_err(|_| Error::Sealed)?;
    let info = LockInfo::parse(&s).ok_or(Error::Sealed)?;
    let held = match f.try_lock() {
        Ok(()) => {
            let _ = f.unlock();
            false
        }
        Err(_) => true,
    };
    Ok((info, held))
}

/// The broker's endpoint: the held lock file and the bound listener.
pub struct Endpoint {
    _lock: File,
    pub listener: UnixListener,
    pub sock: PathBuf,
}

/// Take `broker.lock` (non-blocking), record our identity, and bind the socket. `Ok(None)` if another broker holds it.
pub fn bind(run: &Path) -> Result<Option<Endpoint>> {
    platform::os().ensure_private_dir(run)?;
    let mut lock = ipc::open_private_rw(&run.join(LOCK), false)?;
    if lock.try_lock().is_err() {
        return Ok(None);
    }
    let pid = i32::try_from(std::process::id()).map_err(|_| Error::Internal(100))?;
    let info = LockInfo {
        pid,
        start: ipc::process_start(pid)?,
        exe: ipc::process_exe(pid)?,
    };
    lock.set_len(0)?;
    lock.rewind()?;
    lock.write_all(info.render().as_bytes())?;
    lock.sync_all()?;
    let sock = socket_path(run);
    if sock.as_os_str().len() > ipc::MAX_SOCK_PATH {
        return Err(Error::UnsafePath("runtime dir (path too long)"));
    }
    // we hold the lock, so any existing socket is stale (SPEC §5.4)
    match std::fs::remove_file(&sock) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = UnixListener::bind(&sock)?;
    Ok(Some(Endpoint {
        _lock: lock,
        listener,
        sock,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: a panic is the failure report")]
    use super::*;

    #[test]
    fn lock_info_roundtrip_and_strict_parse() {
        let i = LockInfo {
            pid: 42,
            start: 7,
            exe: PathBuf::from("/opt/a b/keygent"),
        };
        assert_eq!(LockInfo::parse(&i.render()).unwrap(), i);
        for bad in [
            "",
            "v1 1 2 rel/path\n",
            "v2 1 2 /x\n",
            "v1 x 2 /x\n",
            "v1 1 2 /x",
        ] {
            assert!(LockInfo::parse(bad).is_none(), "{bad:?}");
        }
    }
}
