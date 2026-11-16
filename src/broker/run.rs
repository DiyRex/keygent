//! Contained execution of an approved grant (SPEC §5.7 steps 4–6, PLATFORMS "Child containment").
//!
//! - Every pinned program is re-hashed right before exec; a mismatch fails closed (`PolicyMsg::Changed`).
//! - The stored (rewritten) command runs under `/bin/sh -c` with no rc files (`ENV` unset), a minimal env built by the
//!   broker (the client env is never used), stdin `/dev/null`, pipes only, in its own session.
//! - Values reach the child only through env vars and private file bindings (Linux memfd, macOS owner-only files in
//!   the broker run dir, removed at run end and swept at broker start). Bound scripts run from the bytes read at
//!   grant time.
//! - stdout/stderr go through one redactor stream each before any byte leaves the broker.
//! - Limits: runtime deadline, 10 MiB per stream for foreground runs; either kills the session and ends with exit 74.
//!   A client disconnect kills the session immediately. `Signal` frames are forwarded to the process group.

use super::Shared;
use super::log::Level;
use crate::crypto::{self, Secret};
use crate::error::{Error, PolicyMsg};
use crate::platform::ipc;
use crate::policy::resolve::{self, Program};
use crate::proto::frame::{self, ty};
use crate::proto::msg;
use crate::proto::tags::proto as t;
use crate::redact::Redactor;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub const MAX_RUNS: usize = 8;
pub const OUTPUT_CAP: u64 = 10 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
/// Runs up to the default runtime are foreground runs and get the output cap; longer ones stream uncapped (§4.1).
const FOREGROUND: Duration = super::grant::DEFAULT_RUNTIME;
/// After the child exits and the session is killed, how long to wait for the output pipes to drain.
const DRAIN: Duration = Duration::from_secs(2);
/// Signals a client may forward.
const FORWARDABLE: &[i32] = &[libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
/// Prefix of private binding files in the run dir (swept at broker start).
const BINDING_PREFIX: &str = "b-";

static RUNNING: AtomicUsize = AtomicUsize::new(0);

/// A run slot (at most `MAX_RUNS`), released on drop.
pub struct Slot;
impl Drop for Slot {
    fn drop(&mut self) {
        RUNNING.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn take_slot() -> Option<Slot> {
    if RUNNING.fetch_add(1, Ordering::SeqCst) >= MAX_RUNS {
        RUNNING.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(Slot)
}

/// Everything a run needs, taken out of the consumed grant under the state lock.
pub struct Job {
    pub command: String,
    pub cwd: PathBuf,
    /// (env var, value) for `{{keygent:h}}`.
    pub env_secrets: Vec<(String, Secret)>,
    /// (env var, value) for `{{keygent-file:h}}`: the var gets the binding's path.
    pub file_secrets: Vec<(String, Secret)>,
    /// (env var, bytes) of bound scripts: the var gets the private copy's path.
    pub scripts: Vec<(String, Vec<u8>)>,
    pub programs: Vec<Program>,
    pub max_runtime: Duration,
    pub redactor: Arc<Redactor>,
    /// `K_audit` and the run's end record (exit, redaction count and duration are filled in at the end).
    pub audit: (crate::crypto::Subkey, crate::vault::audit::Record<'static>),
}

/// One private binding; removed (macOS) or closed (Linux) on drop.
struct Binding {
    #[cfg(target_os = "linux")]
    _fd: std::fs::File,
    #[cfg(target_os = "macos")]
    path: PathBuf,
}

impl Drop for Binding {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Materialize `data` privately; returns the binding and the path the child uses.
fn bind(
    data: &[u8],
    exec: bool,
    run_dir: &Path,
    keep: &mut Vec<i32>,
) -> Result<(Binding, PathBuf), Error> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = (exec, run_dir);
        let f = ipc::memfd_with(data)?;
        let fd = f.as_raw_fd();
        keep.push(fd);
        Ok((Binding { _fd: f }, PathBuf::from(format!("/dev/fd/{fd}"))))
    }
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = keep;
        let name: String = crypto::random::<12>()?
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let path = run_dir.join(format!("{BINDING_PREFIX}{name}"));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(if exec { 0o700 } else { 0o600 })
            .open(&path)?;
        let b = Binding { path: path.clone() };
        f.write_all(data)?;
        f.sync_all()?;
        Ok((b, path))
    }
}

/// Remove binding files a crashed broker left behind (macOS; Linux memfds die with their process).
pub fn sweep_bindings(run_dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(run_dir) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(BINDING_PREFIX) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn home() -> Option<PathBuf> {
    #[cfg(feature = "test-profile")]
    if let Some(r) = std::env::var_os("KEYGENT_TEST_ROOT") {
        return Some(PathBuf::from(r).join("home"));
    }
    std::env::home_dir()
}

/// Home dir for children and the cwd rule (never the client's `HOME`).
pub fn user_home() -> Option<PathBuf> {
    home()
}

/// The minimal child env (PLATFORMS "Minimal child env"). `LANG`/`LC_*`/`TZ` are not captured at unseal yet, so
/// children run in the C locale.
fn base_env(cmd: &mut Command, path_var: &str) -> Result<(), Error> {
    cmd.env_clear();
    cmd.env("PATH", path_var);
    if let Some(h) = home() {
        cmd.env("HOME", h);
    }
    if let Some(u) = ipc::user_name() {
        cmd.env("USER", &u);
        cmd.env("LOGNAME", &u);
    }
    cmd.env("TMPDIR", ipc::temp_dir());
    #[cfg(target_os = "macos")]
    cmd.env(
        "__CF_USER_TEXT_ENCODING",
        format!("0x{:X}:0x0:0x0", ipc::uid()),
    );
    for (k, v) in [
        ("TERM", "dumb"),
        ("NO_COLOR", "1"),
        ("PAGER", "cat"),
        ("GIT_PAGER", "cat"),
    ] {
        cmd.env(k, v);
    }
    let id: String = crypto::random::<8>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    cmd.env("KEYGENT_RUN_ID", id);
    Ok(())
}

fn send(w: &Mutex<UnixStream>, t: u8, payload: &[u8]) -> bool {
    match w.lock() {
        Ok(mut s) => frame::write(&mut *s, t, payload).is_ok(),
        Err(_) => false,
    }
}

fn send_data(w: &Mutex<UnixStream>, t: u8, data: &[u8]) -> bool {
    for c in data.chunks(CHUNK) {
        match msg::encode_data(c, None) {
            Ok(p) if send(w, t, &p) => {}
            _ => return false,
        }
    }
    true
}

const STOP_NONE: u8 = 0;
const STOP_LIMIT: u8 = 1;
const STOP_GONE: u8 = 2;

struct Flags {
    done: AtomicBool,
    stop: AtomicU8,
    hits: AtomicU64,
}

impl Flags {
    fn stop(&self, why: u8, sid: i32) {
        let _ = self
            .stop
            .compare_exchange(STOP_NONE, why, Ordering::SeqCst, Ordering::SeqCst);
        ipc::kill_session(sid);
    }
}

fn pump(
    mut src: impl Read,
    t: u8,
    red: &Redactor,
    w: &Mutex<UnixStream>,
    cap: Option<u64>,
    sid: i32,
    flags: &Flags,
) {
    let mut st = red.stream();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut out = Vec::with_capacity(CHUNK);
    let mut total = 0u64;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if cap.is_some_and(|c| total > c) {
            flags.stop(STOP_LIMIT, sid);
            break;
        }
        out.clear();
        st.push(buf.get(..n).unwrap_or_default(), &mut out);
        if flags.stop.load(Ordering::SeqCst) == STOP_NONE && !send_data(w, t, &out) {
            flags.stop(STOP_GONE, sid);
        }
    }
    out.clear();
    st.finish(&mut out);
    flags.hits.fetch_add(st.hits, Ordering::SeqCst);
    if flags.stop.load(Ordering::SeqCst) == STOP_NONE {
        let _ = send_data(w, t, &out);
    }
}

fn send_err(s: &mut UnixStream, e: &Error) {
    super::server::send_error(s, e);
}

/// Run `job` and stream it to `s`. Consumes the connection.
pub fn execute(shared: &Shared, mut s: UnixStream, job: Job) {
    // 1. pins: every bound executable must still be the approved file
    for p in &job.programs {
        if let Program::File { path, sha256 } = p
            && resolve::hash_file(path).is_none_or(|h| !crypto::ct_eq(&h, sha256))
        {
            send_err(&mut s, &Error::Policy(PolicyMsg::Changed));
            return;
        }
    }
    // 2. private bindings and the command
    let mut keep = Vec::new();
    let mut bindings = Vec::new();
    let mut cmd = Command::new("/bin/sh");
    if base_env(&mut cmd, &shared.path).is_err() {
        send_err(&mut s, &Error::Internal(140));
        return;
    }
    for (var, value) in &job.file_secrets {
        match bind(value.expose(), false, &shared.dirs.run, &mut keep) {
            Ok((b, p)) => {
                bindings.push(b);
                cmd.env(var, p);
            }
            Err(_) => {
                send_err(&mut s, &Error::Internal(141));
                return;
            }
        }
    }
    for (var, bytes) in &job.scripts {
        match bind(bytes, true, &shared.dirs.run, &mut keep) {
            Ok((b, p)) => {
                bindings.push(b);
                cmd.env(var, p);
            }
            Err(_) => {
                send_err(&mut s, &Error::Internal(141));
                return;
            }
        }
    }
    for (var, value) in &job.env_secrets {
        cmd.env(var, OsStr::from_bytes(value.expose()));
    }
    cmd.arg("-c")
        .arg(&job.command)
        .current_dir(&job.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // 3. spawn contained
    let mut child = match ipc::spawn_contained(&mut cmd, keep) {
        Ok(c) => c,
        Err(_) => {
            send_err(&mut s, &Error::Internal(142));
            return;
        }
    };
    drop(cmd); // the env copy holding values is freed (zeroed by the allocator) now
    drop(job.env_secrets);
    drop(job.file_secrets);
    let sid = i32::try_from(child.id()).unwrap_or(0);
    if let Ok(mut r) = shared.runs.lock() {
        r.push(sid);
    }
    shared.log.event(Level::Info, "run_started", None);
    let flags = Arc::new(Flags {
        done: AtomicBool::new(false),
        stop: AtomicU8::new(STOP_NONE),
        hits: AtomicU64::new(0),
    });
    let started = std::time::Instant::now();
    let _ = s.set_read_timeout(None);
    let writer = match s.try_clone() {
        Ok(w) => Arc::new(Mutex::new(w)),
        Err(_) => {
            ipc::kill_session(sid);
            let _ = child.wait();
            return;
        }
    };
    let cap = (job.max_runtime <= FOREGROUND).then_some(OUTPUT_CAP);
    let (tx, rx) = mpsc::channel::<()>();
    let mut pumps = 0u8;
    for (src, t) in [
        (
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            ty::STDOUT,
        ),
        (
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            ty::STDERR,
        ),
    ] {
        let Some(src) = src else { continue };
        let (red, w, f, tx) = (
            job.redactor.clone(),
            writer.clone(),
            flags.clone(),
            tx.clone(),
        );
        if std::thread::Builder::new()
            .stack_size(super::THREAD_STACK)
            .spawn(move || {
                pump(src, t, &red, &w, cap, sid, &f);
                let _ = tx.send(());
            })
            .is_ok()
        {
            pumps = pumps.saturating_add(1);
        }
    }
    // client frames: forwarded signals; EOF or error = the client is gone → kill now
    if let Ok(mut r) = s.try_clone() {
        let f = flags.clone();
        let _ = std::thread::Builder::new()
            .stack_size(super::THREAD_STACK)
            .spawn(move || {
                loop {
                    match frame::read(&mut r) {
                        Ok(fr) if fr.ty == ty::SIGNAL => {
                            if let Ok(n) = msg::decode_u32(&fr.payload, t::SIGNAL)
                                && let Ok(n) = i32::try_from(n)
                                && FORWARDABLE.contains(&n)
                            {
                                ipc::signal_group(sid, n);
                            }
                        }
                        Ok(_) => {}
                        Err(_) => {
                            if !f.done.load(Ordering::SeqCst) {
                                f.stop(STOP_GONE, sid);
                            }
                            return;
                        }
                    }
                }
            });
    }
    // runtime limit
    {
        let f = flags.clone();
        let deadline = super::clock::Deadline::after(job.max_runtime);
        let _ = std::thread::Builder::new()
            .stack_size(super::THREAD_STACK)
            .spawn(move || {
                while !f.done.load(Ordering::SeqCst) {
                    if deadline.expired() {
                        f.stop(STOP_LIMIT, sid);
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
    }
    let status = child.wait();
    // anything left in the session (`cmd &`, nohup) dies with the run
    ipc::kill_session(sid);
    for _ in 0..pumps {
        if rx.recv_timeout(DRAIN).is_err() {
            break;
        }
    }
    flags.done.store(true, Ordering::SeqCst);
    if let Ok(mut r) = shared.runs.lock() {
        r.retain(|&p| p != sid);
    }
    drop(bindings);
    let code: i32 = match status {
        Ok(st) => {
            use std::os::unix::process::ExitStatusExt;
            st.code()
                .or_else(|| st.signal().map(|n| n.saturating_add(128)))
                .unwrap_or(1)
        }
        Err(_) => 1,
    };
    let (key, mut end) = job.audit;
    end.exit = Some(code);
    end.redactions = Some(flags.hits.load(Ordering::SeqCst));
    end.dur_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    end.decision = Some(match flags.stop.load(Ordering::SeqCst) {
        STOP_LIMIT => "limit",
        STOP_GONE => "client_gone",
        _ => "end",
    });
    // the run already happened; a failed end record is logged, not hidden
    if crate::vault::audit::append(&shared.dirs, &key, &end).is_err() {
        shared.log.event(Level::Error, "audit_append_failed", None);
    }
    drop(key);
    match flags.stop.load(Ordering::SeqCst) {
        STOP_LIMIT => {
            shared.log.event(Level::Info, "run_limit", None);
            if let Ok(mut w) = writer.lock() {
                super::server::send_error(
                    &mut w,
                    &Error::Policy(PolicyMsg::Limit(super::grant::minutes(job.max_runtime))),
                );
            }
        }
        STOP_GONE => shared.log.event(Level::Info, "run_client_gone", None),
        _ => {
            shared.log.event(
                Level::Info,
                "run_exit",
                Some(u64::try_from(code).unwrap_or(0)),
            );
            if let Ok(p) = msg::encode_u32(t::EXIT_CODE, u32::try_from(code).unwrap_or(1)) {
                let _ = send(&writer, ty::EXIT, &p);
            }
        }
    }
    let _ = s.shutdown(std::net::Shutdown::Both);
}
