//! Unix IPC and process primitives for the broker endpoint (SPEC §5.4, PLATFORMS "IPC access", "Exclusive bind",
//! "Broker start"): runtime dir, peer credentials, process identity (start time + executable), broker hardening,
//! termination signals and detached spawn.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// `EACCES`, for callers that must tell "permission denied" apart without naming libc.
#[cfg(target_os = "linux")]
pub const EACCES: i32 = libc::EACCES;

/// Max `sun_path` length we accept (macOS 104 incl. NUL, Linux 108).
pub const MAX_SOCK_PATH: usize = 100;

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// Fixed per-user runtime dir (PLATFORMS §Locations), never from env. Created owner-only and verified by the caller.
pub fn runtime_dir(state: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let _ = state;
        let mut buf = vec![0u8; 1024];
        // SAFETY: buffer valid for its length; confstr writes a NUL-terminated string.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n > 0 && n <= buf.len() {
            buf.truncate(n.saturating_sub(1));
            use std::os::unix::ffi::OsStrExt;
            let p = PathBuf::from(std::ffi::OsStr::from_bytes(&buf)).join("keygent");
            if p.is_absolute() && p.as_os_str().len().saturating_add(12) <= MAX_SOCK_PATH {
                return p;
            }
        }
        PathBuf::from(format!("/tmp/keygent-{}", uid()))
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let run = PathBuf::from(format!("/run/user/{}", uid()));
        match std::fs::symlink_metadata(&run) {
            Ok(m) if m.is_dir() && m.uid() == uid() && m.mode() & 0o077 == 0 => run.join("keygent"),
            _ => state.join("run"),
        }
    }
}

/// Peer (uid, pid) of a connected Unix socket.
pub fn peer_cred(s: &UnixStream) -> Result<(u32, i32)> {
    let fd = s.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        let mut c = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
            .map_err(|_| Error::Internal(90))?;
        // SAFETY: valid fd, out-pointer and length.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut c).cast(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((c.uid, c.pid))
    }
    #[cfg(target_os = "macos")]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: valid fd and out-pointers.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut pid: libc::pid_t = 0;
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>())
            .map_err(|_| Error::Internal(90))?;
        // SAFETY: SOL_LOCAL(0)/LOCAL_PEERPID(2) on a connected unix socket; valid out-pointer and length.
        let r = unsafe {
            libc::getsockopt(fd, 0, libc::LOCAL_PEERPID, (&raw mut pid).cast(), &mut len)
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((uid, pid))
    }
}

/// Process start time (opaque, monotonic per boot), used with the pid to defeat PID reuse.
pub fn process_start(pid: i32) -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        // field 22 (starttime) counted after the last ')' (comm may contain spaces/parens)
        let rest = s
            .rsplit_once(')')
            .map(|(_, r)| r)
            .ok_or(Error::Internal(91))?;
        rest.split_whitespace()
            .nth(19)
            .and_then(|v| v.parse().ok())
            .ok_or(Error::Internal(92))
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: proc_bsdinfo is POD.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
            .map_err(|_| Error::Internal(93))?;
        // SAFETY: valid out-buffer of `size` bytes.
        let n = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if n != size {
            return Err(Error::Internal(94));
        }
        Ok(info
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec))
    }
}

/// Executable path of a running process.
pub fn process_exe(pid: i32) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(std::fs::read_link(format!("/proc/{pid}/exe"))?)
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 4 * 1024];
        let len = u32::try_from(buf.len()).map_err(|_| Error::Internal(95))?;
        // SAFETY: valid buffer of `len` bytes.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), len) };
        let n = usize::try_from(n).map_err(|_| Error::Internal(96))?;
        if n == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        buf.truncate(n);
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
    }
}

/// What hardening took effect (reported by `status`/doctor).
#[derive(Debug, Clone, Copy, Default)]
pub struct Hardening {
    pub no_dumps: bool,
    pub mlockall: bool,
}

/// Broker-only hardening (PLATFORMS "No dumps / debug"): no core dumps, not dumpable / deny attach, and on Linux
/// `mlockall` (degrades to arena-only if RLIMIT_MEMLOCK is too low). Never `NO_NEW_PRIVS` (it would be inherited).
pub fn harden_broker() -> Hardening {
    let mut h = Hardening::default();
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointer.
    let core = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } == 0;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl with integer arguments.
        let nd = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
        h.no_dumps = core && nd;
        // SAFETY: no pointers involved.
        h.mlockall = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } == 0;
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH takes no address/data.
        let deny = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == 0;
        h.no_dumps = core && deny;
    }
    h
}

/// Block SIGTERM/SIGHUP/SIGINT in the calling thread (call before spawning threads so all inherit the mask);
/// `wait_term_signal` then receives them synchronously.
pub fn block_term_signals() {
    // SAFETY: sigset manipulation on a local set; pthread_sigmask on the current thread.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

pub fn wait_term_signal() -> i32 {
    // SAFETY: as above; sigwait writes the received signal into `sig`.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::sigaddset(&mut set, libc::SIGINT);
        let mut sig = 0;
        libc::sigwait(&set, &mut sig);
        sig
    }
}

/// Spawn `exe broker` detached: cleared env, stdin = a pipe (the DEK handoff), stdout/stderr null, new session
/// (PLATFORMS "Broker start": spawn with cleared env, one inherited pipe, setsid). Rust marks every other fd CLOEXEC.
pub fn spawn_broker(exe: &Path) -> Result<Child> {
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(exe);
    c.arg("broker")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(feature = "test-profile")]
    for k in ["KEYGENT_TEST_ROOT", "KEYGENT_TEST_FAST_KDF"] {
        if let Some(v) = std::env::var_os(k) {
            c.env(k, v);
        }
    }
    // SAFETY: setsid is async-signal-safe and touches no Rust state.
    unsafe {
        c.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c.spawn().map_err(Error::from)
}

/// Open (creating if missing) an owner-only file for read+write or append without following symlinks, and verify
/// owner and mode on the opened handle (lock files, broker log).
pub fn open_private_rw(path: &Path, append: bool) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(!append)
        .write(!append)
        .append(append)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                Error::UnsafePath("runtime file")
            } else {
                e.into()
            }
        })?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != uid() || m.mode() & 0o077 != 0 {
        return Err(Error::UnsafePath("runtime file"));
    }
    Ok(f)
}

/// Verify an existing private dir without creating it (client side: SPEC §5.4 `lstat` before every connect).
pub fn check_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(dir)?;
    if !m.is_dir() || m.uid() != uid() || m.mode() & 0o077 != 0 {
        return Err(Error::UnsafePath("runtime dir"));
    }
    Ok(())
}
