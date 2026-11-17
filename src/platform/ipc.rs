//! Unix IPC and process primitives for the broker endpoint (SPEC §5.4, PLATFORMS "IPC access", "Exclusive bind",
//! "Broker start"): runtime dir, peer credentials, process identity (start time + executable), broker hardening,
//! termination signals and detached spawn.
#![allow(
    unsafe_code,
    reason = "platform layer: the only FFI in the crate; every block carries a SAFETY comment"
)]

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

/// Core-dump limit captured before hardening, restored in every child so children get default process state.
static CORE_LIMIT: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

/// Broker-only hardening (PLATFORMS "No dumps / debug"): no core dumps, not dumpable / deny attach, and on Linux
/// `mlockall` (degrades to arena-only if RLIMIT_MEMLOCK is too low) plus child subreaper. Never `NO_NEW_PRIVS`.
pub fn harden_broker() -> Hardening {
    let mut h = Hardening::default();
    let mut orig = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid out-pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut orig) } == 0 {
        let _ = CORE_LIMIT.set((orig.rlim_cur, orig.rlim_max));
    }
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
        // orphans of a run reparent to the broker, which kills and reaps them (PLATFORMS "Child containment")
        // SAFETY: prctl with integer arguments.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
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
        .read(true)
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

/// Spawn a run's child contained (PLATFORMS "Child containment", ADR 0009): its own session (pgid = sid = pid),
/// Linux `PR_SET_PDEATHSIG(SIGKILL)`, the signal mask cleared and `RLIMIT_CORE` restored to its pre-hardening value.
/// The caller sets env, cwd and stdio (stdin is always /dev/null for runs). `keep_fds` (close-on-exec memfds of this
/// run only) are made inheritable in the child alone, so concurrent runs never see each other's bindings.
pub fn spawn_contained(cmd: &mut Command, keep_fds: Vec<i32>) -> std::io::Result<Child> {
    use std::os::unix::process::CommandExt;
    let (cur, max) = CORE_LIMIT.get().copied().unwrap_or((0, 0));
    // SAFETY: only async-signal-safe calls (setsid, prctl, sigprocmask, setrlimit, fcntl) on data captured before
    // fork; no allocation.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &keep_fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            let rl = libc::rlimit {
                rlim_cur: cur,
                rlim_max: max,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &rl);
            Ok(())
        });
    }
    cmd.spawn()
}

fn all_pids() -> Vec<i32> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc")
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        let mut pids = vec![0 as libc::c_int; 16384];
        let bytes = libc::c_int::try_from(pids.len().saturating_mul(4)).unwrap_or(0);
        // SAFETY: buffer valid for `bytes` bytes.
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
        pids.truncate(usize::try_from(n).unwrap_or(0));
        pids
    }
}

/// Signal the run's process group (interrupt forwarding).
pub fn signal_group(pgid: i32, sig: i32) {
    if pgid > 1 {
        // SAFETY: kill with a negative pid signals the process group; no memory involved.
        unsafe { libc::kill(pgid.wrapping_neg(), sig) };
    }
}

/// Kill every process of a run (ADR 0009): the process group, then every pid whose session id is the run's session
/// (catches `&`/`nohup` survivors, Apple binaries included). Orphans reparented to the broker (Linux subreaper) are
/// reaped here, retrying for up to 1 s until nothing but the leader is left; the leader itself is reaped by its
/// `Child::wait`. A survivor that called `setsid()` itself escapes this sweep (documented best effort).
pub fn kill_session(sid: i32) {
    if sid <= 1 {
        return;
    }
    signal_group(sid, libc::SIGKILL);
    let me = i32::try_from(std::process::id()).unwrap_or(0);
    for _ in 0..100 {
        let mut left = false;
        for pid in all_pids() {
            // SAFETY: getsid/kill/waitpid on a pid value; no memory involved (null status pointer is allowed).
            if pid > 1 && pid != me && unsafe { libc::getsid(pid) } == sid {
                // SAFETY: as above.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                if pid != sid {
                    // SAFETY: as above.
                    unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
                    left = true;
                }
            }
        }
        if !left {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// The user's login name from the passwd database (for the child's USER/LOGNAME).
pub fn user_name() -> Option<String> {
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: passwd is POD.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: valid pointers and lengths; `out` is set to &pw or null.
    let rc =
        unsafe { libc::getpwuid_r(uid(), &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pw.pw_name.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated string inside `buf`, alive here.
    let name = unsafe { std::ffi::CStr::from_ptr(pw.pw_name) };
    name.to_str().ok().map(str::to_owned)
}

/// Per-user temp dir for children (`TMPDIR`): macOS `_CS_DARWIN_USER_TEMP_DIR`, Linux `/tmp`.
pub fn temp_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 1024];
        // SAFETY: buffer valid for its length.
        let n = unsafe {
            libc::confstr(
                libc::_CS_DARWIN_USER_TEMP_DIR,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n > 1 && n <= buf.len() {
            buf.truncate(n.saturating_sub(1));
            use std::os::unix::ffi::OsStrExt;
            return PathBuf::from(std::ffi::OsStr::from_bytes(&buf));
        }
        PathBuf::from("/tmp")
    }
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/tmp")
    }
}

/// Linux file binding (PLATFORMS "File bindings"): an anonymous memfd holding the value, inherited by the child and
/// reachable as `/dev/fd/N`. Never touches a filesystem. Close-on-exec until `spawn_contained` clears it in the child.
#[cfg(target_os = "linux")]
pub fn memfd_with(data: &[u8]) -> Result<std::fs::File> {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    // SAFETY: NUL-terminated name and flags only.
    let fd = unsafe { libc::memfd_create(c"keygent".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fd is a fresh, owned descriptor.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    f.write_all(data)?;
    Ok(f)
}
