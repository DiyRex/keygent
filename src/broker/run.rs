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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
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
/// Prefix of scratch HOME dirs in the run dir (swept at broker start).
const SCRATCH_PREFIX: &str = "h-";

/// A scratch HOME (rule `home = "scratch"`), removed on drop.
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch_home(run_dir: &Path, cmd: &mut Command) -> Result<Scratch, Error> {
    use std::os::unix::fs::DirBuilderExt;
    let name: String = crypto::random_hex::<12>()?;
    let root = run_dir.join(format!("{SCRATCH_PREFIX}{name}"));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let s = Scratch(root.clone());
    for (var, sub) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_STATE_HOME", "state"),
    ] {
        let d = root.join(sub);
        std::fs::DirBuilder::new().mode(0o700).create(&d)?;
        cmd.env(var, d);
    }
    Ok(s)
}

/// The command to spawn: `/bin/sh -c <stored command>`, or (allow-rule path) the pinned program itself. On Linux the
/// program is opened once, hashed from that descriptor and exec'd through it (`/dev/fd/N`), so it can't be swapped
/// between the check and the exec; macOS has no `fexecve`, so it is hashed and then exec'd by path (a same-user race,
/// documented T2 residual).
fn base_command(job: &Job, keep: &mut Vec<i32>, held: &mut Vec<Binding>) -> Result<Command, Error> {
    let Some(Direct {
        exe,
        sha256: sha,
        argv,
    }) = &job.direct
    else {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(&job.command);
        return Ok(c);
    };
    use std::os::unix::process::CommandExt;
    let arg0 = argv.first().cloned().unwrap_or_default();
    #[cfg(target_os = "linux")]
    let mut c = {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open(exe)?;
        // hash through this very fd, then exec through it (no swap window)
        match crypto::sha256_reader(&f, resolve::MAX_EXE)? {
            Some(h) if crypto::ct_eq(&h, sha) => {}
            _ => return Err(Error::Policy(PolicyMsg::Changed)),
        }
        let fd = f.as_raw_fd();
        keep.push(fd);
        held.push(Binding { _fd: f });
        Command::new(format!("/dev/fd/{fd}"))
    };
    #[cfg(target_os = "macos")]
    let mut c = {
        let _ = (keep, held);
        if resolve::hash_file(exe).is_none_or(|h| !crypto::ct_eq(&h, sha)) {
            return Err(Error::Policy(PolicyMsg::Changed));
        }
        Command::new(exe)
    };
    c.arg0(arg0).args(argv.iter().skip(1));
    Ok(c)
}

/// A run's entry in `Shared::runs` (what `seal` kills), removed on every exit path including early returns.
struct RunEntry<'a> {
    shared: &'a Shared,
    sid: i32,
}

impl<'a> RunEntry<'a> {
    fn register(shared: &'a Shared, sid: i32) -> Self {
        super::lock(&shared.runs).push(sid);
        RunEntry { shared, sid }
    }
}

impl Drop for RunEntry<'_> {
    fn drop(&mut self) {
        super::lock(&self.shared.runs).retain(|&p| p != self.sid);
    }
}

/// Everything a run needs, taken out of the consumed grant under the state lock.
pub struct Job {
    pub command: String,
    pub cwd: PathBuf,
    /// (env var, value) for `{{keygent:h}}`.
    pub env_secrets: Vec<(String, Secret)>,
    /// (env var, value) for `{{keygent-file:h}}`: the var gets the binding's path.
    pub file_secrets: Vec<(String, Secret)>,
    /// Custody credentials (ADR 0022): the env holds their dummies; this run's proxy holds the values.
    pub custody: Vec<super::proxy::Cred>,
    /// (env var, bytes) of bound scripts: the var gets the private copy's path.
    pub scripts: Vec<(String, Vec<u8>)>,
    pub programs: Vec<Program>,
    /// Allow-rule path: exec this pinned program with this argv, no shell (`command` is unused).
    pub direct: Option<Direct>,
    /// Empty temp HOME + XDG dirs for this run.
    pub scratch: bool,
    /// `capture <handle>`: stdout is stored as this new handle (never sent); stderr is held and redacted at the end.
    pub capture: Option<String>,
    pub max_runtime: Duration,
    pub redactor: Arc<Redactor>,
    /// The run's end record, completed (exit, redactions, duration, decision) and appended when the run ends.
    pub audit: EndRecord,
}

/// The pinned program of an allow-rule run.
pub struct Direct {
    pub exe: PathBuf,
    pub sha256: [u8; 32],
    pub argv: Vec<String>,
}

/// `K_audit` plus the prepared end-of-run audit record.
pub struct EndRecord {
    pub key: crate::crypto::Subkey,
    pub record: crate::vault::audit::Record<'static>,
    /// Custody egress summaries, appended before the end record (ADR 0022).
    pub egress: Vec<crate::vault::audit::Record<'static>>,
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
        let name: String = crypto::random_hex::<12>()?;
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
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(BINDING_PREFIX) {
                let _ = std::fs::remove_file(e.path());
            } else if n.starts_with(SCRATCH_PREFIX) {
                let _ = std::fs::remove_dir_all(e.path());
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
    let id: String = crypto::random_hex::<8>()?;
    cmd.env("KEYGENT_RUN_ID", id);
    Ok(())
}

fn send(w: &Mutex<UnixStream>, t: u8, payload: &[u8]) -> bool {
    frame::write(&mut *super::lock(w), t, payload).is_ok()
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

/// Why a run ended early. Set once (first reason wins); setting it kills the session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Stop {
    None = 0,
    /// Runtime or output limit (exit 74).
    Limit = 1,
    /// The client disconnected.
    ClientGone = 2,
    /// Captured stdout exceeded the 64 KiB value limit.
    TooBig = 3,
    /// A guard thread (pump, client watcher, runtime limit) couldn't start (fail closed).
    Failed = 4,
}

impl Stop {
    fn from_u8(v: u8) -> Stop {
        match v {
            1 => Stop::Limit,
            2 => Stop::ClientGone,
            3 => Stop::TooBig,
            4 => Stop::Failed,
            _ => Stop::None,
        }
    }
}

/// Captured stdout cap (values are ≤ 64 KiB after trimming; a little slack for surrounding whitespace).
const CAPTURE_MAX: usize = 64 * 1024 + 1024;
/// Held stderr of a capture run; the rest is dropped.
const CAPTURE_STDERR_MAX: usize = 1024 * 1024;

/// State shared by a run's threads.
struct Flags {
    sid: i32,
    done: AtomicBool,
    stop: AtomicU8,
    hits: AtomicU64,
}

impl Flags {
    fn new(sid: i32) -> Self {
        Flags {
            sid,
            done: AtomicBool::new(false),
            stop: AtomicU8::new(Stop::None as u8),
            hits: AtomicU64::new(0),
        }
    }

    /// Record why the run stops and kill its session — once, by whichever thread gets there first (a full
    /// session sweep scans every pid, so it isn't repeated per thread).
    fn stop(&self, why: Stop) {
        if self
            .stop
            .compare_exchange(
                Stop::None as u8,
                why as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            ipc::kill_session(self.sid);
        }
    }

    fn stopped(&self) -> Stop {
        Stop::from_u8(self.stop.load(Ordering::Acquire))
    }
}

/// Capture mode: keep raw bytes in the broker. Over `cap`: stop the run (`hard`) or drop the rest.
fn collect(
    mut src: impl Read,
    buf: &Mutex<Zeroizing<Vec<u8>>>,
    cap: usize,
    hard: bool,
    flags: &Flags,
) {
    let mut chunk = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        let n = match src.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut b = super::lock(buf);
        if b.len().saturating_add(n) > cap {
            if hard {
                drop(b);
                flags.stop(Stop::TooBig);
                break;
            }
            continue;
        }
        if b.len().saturating_add(n) > b.capacity() {
            // grow without leaving partial copies of the value behind
            let mut grown = Zeroizing::new(Vec::with_capacity(
                cap.min(b.len().saturating_add(n).saturating_mul(2)),
            ));
            grown.extend_from_slice(&b);
            *b = grown;
        }
        b.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
}

/// Stream one output pipe through its own redactor stream to the client.
fn pump(
    mut src: impl Read,
    t: u8,
    red: &Redactor,
    w: &Mutex<UnixStream>,
    cap: Option<u64>,
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
            flags.stop(Stop::Limit);
            break;
        }
        out.clear();
        st.push(buf.get(..n).unwrap_or_default(), &mut out);
        if flags.stopped() == Stop::None && !send_data(w, t, &out) {
            flags.stop(Stop::ClientGone);
        }
    }
    out.clear();
    st.finish(&mut out);
    flags.hits.fetch_add(st.hits, Ordering::Relaxed);
    if flags.stopped() == Stop::None {
        let _ = send_data(w, t, &out);
    }
}

/// A command ready to spawn, plus everything that must outlive the child.
struct Prepared {
    cmd: Command,
    /// Close-on-exec fds the child alone inherits (Linux memfds and the pinned program).
    keep: Vec<i32>,
    bindings: Vec<Binding>,
    scratch: Option<Scratch>,
}

/// Steps 1–2: re-check every pin, build the command, env and private bindings. Policy errors pass through; any other
/// failure is an internal error naming its step.
fn prepare(shared: &Shared, job: &Job, proxy_url: Option<&str>) -> Result<Prepared, Error> {
    // every bound executable must still be the approved file
    for p in &job.programs {
        if let Program::File { path, sha256 } = p
            && resolve::hash_file(path).is_none_or(|h| !crypto::ct_eq(&h, sha256))
        {
            return Err(Error::Policy(PolicyMsg::Changed));
        }
    }
    let mut keep = Vec::new();
    let mut bindings = Vec::new();
    let mut cmd = base_command(job, &mut keep, &mut bindings).map_err(|e| match e {
        Error::Policy(_) => e,
        _ => Error::Internal(146),
    })?;
    base_env(&mut cmd, &shared.path).map_err(|_| Error::Internal(140))?;
    let scratch = if job.scratch {
        Some(scratch_home(&shared.dirs.run, &mut cmd).map_err(|_| Error::Internal(147))?)
    } else {
        None
    };
    let files = job.file_secrets.iter().map(|(v, s)| (v, s.expose(), false));
    let scripts = job.scripts.iter().map(|(v, b)| (v, b.as_slice(), true));
    for (var, data, exec) in files.chain(scripts) {
        let (b, path) =
            bind(data, exec, &shared.dirs.run, &mut keep).map_err(|_| Error::Internal(141))?;
        bindings.push(b);
        cmd.env(var, path);
    }
    for (var, value) in &job.env_secrets {
        cmd.env(var, OsStr::from_bytes(value.expose()));
    }
    if let Some(u) = proxy_url {
        cmd.env("KEYGENT_PROXY_URL", u);
    }
    cmd.current_dir(&job.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(Prepared {
        cmd,
        keep,
        bindings,
        scratch,
    })
}

/// Raw output held back in capture mode.
#[derive(Default)]
struct Held {
    out: Arc<Mutex<Zeroizing<Vec<u8>>>>,
    err: Arc<Mutex<Zeroizing<Vec<u8>>>>,
}

/// Start the output pumps, the client watcher (signals, disconnect) and the runtime limit. Returns the number of
/// pumps to drain and whether every guard started (if not, the caller must stop the run: fail closed).
fn spawn_guards(
    child: &mut std::process::Child,
    job: &Job,
    s: &UnixStream,
    writer: &Arc<Mutex<UnixStream>>,
    flags: &Arc<Flags>,
    held: &Held,
    tx: &mpsc::Sender<()>,
) -> (u8, bool) {
    let cap = (job.max_runtime <= FOREGROUND).then_some(OUTPUT_CAP);
    let mut pumps = 0u8;
    let mut ok = true;
    let pipes = [
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
    ];
    for (src, t) in pipes {
        let Some(src) = src else { continue };
        let (red, w, f, tx) = (
            job.redactor.clone(),
            writer.clone(),
            flags.clone(),
            tx.clone(),
        );
        let buf = if t == ty::STDOUT {
            held.out.clone()
        } else {
            held.err.clone()
        };
        let capturing = job.capture.is_some();
        let spawned = std::thread::Builder::new()
            .stack_size(super::THREAD_STACK)
            .spawn(move || {
                if capturing {
                    let (limit, hard) = if t == ty::STDOUT {
                        (CAPTURE_MAX, true)
                    } else {
                        (CAPTURE_STDERR_MAX, false)
                    };
                    collect(src, &buf, limit, hard, &f);
                } else {
                    pump(src, t, &red, &w, cap, &f);
                }
                let _ = tx.send(());
            });
        if spawned.is_ok() {
            pumps = pumps.saturating_add(1);
        } else {
            ok = false;
        }
    }
    // client frames: forwarded signals; EOF or error = the client is gone → kill now
    match s.try_clone() {
        Ok(mut r) => {
            let f = flags.clone();
            ok &= std::thread::Builder::new()
                .stack_size(super::THREAD_STACK)
                .spawn(move || {
                    loop {
                        match frame::read(&mut r) {
                            Ok(fr) if fr.ty == ty::SIGNAL => {
                                if let Ok(n) = msg::decode_u32(&fr.payload, t::SIGNAL)
                                    && let Ok(n) = i32::try_from(n)
                                    && FORWARDABLE.contains(&n)
                                {
                                    ipc::signal_group(f.sid, n);
                                }
                            }
                            Ok(_) => {}
                            Err(_) => {
                                if !f.done.load(Ordering::Acquire) {
                                    f.stop(Stop::ClientGone);
                                }
                                return;
                            }
                        }
                    }
                })
                .is_ok();
        }
        Err(_) => ok = false,
    }
    // runtime limit
    let f = flags.clone();
    let deadline = super::clock::Deadline::after(job.max_runtime);
    ok &= std::thread::Builder::new()
        .stack_size(super::THREAD_STACK)
        .spawn(move || {
            while !f.done.load(Ordering::Acquire) {
                if deadline.expired() {
                    f.stop(Stop::Limit);
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
        .is_ok();
    (pumps, ok)
}

/// Capture: store stdout as the new handle on success, then release stderr redacted with the session redactor **and**
/// the new value. Returns the error to report instead of an exit code, if any.
fn finish_capture(
    shared: &Shared,
    job: &Job,
    h: &str,
    code: i32,
    held: &Held,
    writer: &Mutex<UnixStream>,
    flags: &Flags,
) -> Option<Error> {
    // move the buffers out (they stay in their wiping wrappers); never copy the value into plain memory
    let raw: Zeroizing<Vec<u8>> = std::mem::take(&mut *super::lock(&held.out));
    let value = Secret::from_slice(raw.trim_ascii());
    drop(raw);
    let stderr_raw: Zeroizing<Vec<u8>> = std::mem::take(&mut *super::lock(&held.err));
    let (mut err_out, mut hits) = job.redactor.redact_all(&stderr_raw);
    drop(stderr_raw);
    if let Ok(r) = Redactor::new(std::iter::once((h, value.expose()))) {
        let (again, n) = r.redact_all(&err_out);
        err_out = again;
        hits = hits.saturating_add(n);
    }
    flags.hits.fetch_add(hits, Ordering::Relaxed);
    let _ = send_data(writer, ty::STDERR, &err_out);
    match flags.stopped() {
        Stop::TooBig => Some(Error::ValueSize),
        Stop::None if code == 0 => super::server::store_capture(shared, h, &value).err(),
        _ => None,
    }
}

/// Append the end record, then tell the client how the run ended (exit code or one `keygent:` line).
fn report(
    shared: &Shared,
    job: Job,
    code: i32,
    started: std::time::Instant,
    outcome: Option<&Error>,
    writer: &Mutex<UnixStream>,
    flags: &Flags,
) {
    let capture = job.capture.is_some();
    let EndRecord {
        key,
        record: mut end,
        egress,
    } = job.audit;
    for rec in egress {
        if crate::vault::audit::append(&shared.dirs, &key, &rec).is_err() {
            shared.log.event(Level::Error, "audit_append_failed", None);
        }
    }
    end.exit = Some(code);
    end.redactions = Some(flags.hits.load(Ordering::Relaxed));
    end.dur_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    end.decision = Some(match flags.stopped() {
        Stop::Limit => "limit",
        Stop::ClientGone => "client_gone",
        Stop::TooBig => "capture_too_big",
        Stop::Failed => "internal",
        Stop::None if capture && code == 0 && outcome.is_none() => "captured",
        Stop::None if capture && code == 0 => "capture_refused",
        Stop::None => "end",
    });
    // the run already happened; a failed end record is logged, not hidden
    if crate::vault::audit::append(&shared.dirs, &key, &end).is_err() {
        shared.log.event(Level::Error, "audit_append_failed", None);
    }
    drop(key);
    let send_error = |e: &Error| super::server::send_error(&mut super::lock(writer), e);
    match (flags.stopped(), outcome) {
        (Stop::Limit, _) => {
            shared.log.event(Level::Info, "run_limit", None);
            send_error(&Error::Policy(PolicyMsg::Limit(super::grant::minutes(
                job.max_runtime,
            ))));
        }
        (Stop::ClientGone, _) => shared.log.event(Level::Info, "run_client_gone", None),
        (Stop::Failed, _) => send_error(&Error::Internal(149)),
        (_, Some(e)) => send_error(e),
        _ => {
            shared.log.event(
                Level::Info,
                "run_exit",
                Some(u64::try_from(code).unwrap_or(0)),
            );
            if let Ok(p) = msg::encode_u32(t::EXIT_CODE, u32::try_from(code).unwrap_or(1)) {
                let _ = send(writer, ty::EXIT, &p);
            }
        }
    }
}

/// Run `job` and stream it to `s`. Consumes the connection.
pub fn execute(shared: &Arc<Shared>, mut s: UnixStream, mut job: Job) {
    // ADR 0022: custody values live in this run's proxy, never in the child
    let egress: Arc<Mutex<Vec<super::proxy::Outcome>>> = Arc::default();
    let proxy = if job.custody.is_empty() {
        None
    } else {
        match start_proxy(shared, &mut job, &egress) {
            Ok(p) => Some(p),
            Err(e) => return super::server::send_error(&mut s, &e),
        }
    };
    let url = proxy.as_ref().map(super::proxy::Proxy::url);
    let Prepared {
        mut cmd,
        keep,
        bindings,
        scratch,
    } = match prepare(shared, &job, url.as_deref()) {
        Ok(p) => p,
        Err(e) => return super::server::send_error(&mut s, &e),
    };
    // step 3: spawn contained
    let mut child = match ipc::spawn_contained(&mut cmd, keep) {
        Ok(c) => c,
        Err(_) => return super::server::send_error(&mut s, &Error::Internal(142)),
    };
    drop(cmd); // the env copy holding values is freed (zeroed by the allocator) now
    drop(std::mem::take(&mut job.env_secrets));
    drop(std::mem::take(&mut job.file_secrets));
    let sid = i32::try_from(child.id()).unwrap_or(0);
    let registered = RunEntry::register(shared, sid);
    // a seal that copied the run list before our push must not miss us (no PDEATHSIG on macOS)
    if shared.is_sealing() {
        ipc::kill_session(sid);
        let _ = child.wait();
        return;
    }
    shared.log.event(Level::Info, "run_started", None);
    let flags = Arc::new(Flags::new(sid));
    let started = std::time::Instant::now();
    let _ = s.set_read_timeout(None);
    let Ok(writer) = s.try_clone().map(|w| Arc::new(Mutex::new(w))) else {
        ipc::kill_session(sid);
        let _ = child.wait();
        return;
    };
    let held = Held::default();
    let (tx, rx) = mpsc::channel::<()>();
    let (pumps, guards_ok) = spawn_guards(&mut child, &job, &s, &writer, &flags, &held, &tx);
    if !guards_ok {
        shared
            .log
            .event(Level::Error, "run_guard_spawn_failed", None);
        flags.stop(Stop::Failed);
    }
    let status = child.wait();
    // anything left in the session (`cmd &`, nohup) dies with the run
    ipc::kill_session(sid);
    for _ in 0..pumps {
        if rx.recv_timeout(DRAIN).is_err() {
            break;
        }
    }
    flags.done.store(true, Ordering::Release);
    drop(proxy); // stops the listener; in-flight requests end with their connections
    drop(registered);
    drop(bindings);
    drop(scratch);
    let code: i32 = match status {
        Ok(st) => {
            use std::os::unix::process::ExitStatusExt;
            st.code()
                .or_else(|| st.signal().map(|n| n.saturating_add(128)))
                .unwrap_or(1)
        }
        Err(_) => 1,
    };
    let outcome = match &job.capture {
        Some(h) if flags.stopped() != Stop::ClientGone => {
            let h = h.clone();
            finish_capture(shared, &job, &h, code, &held, &writer, &flags)
        }
        _ => None,
    };
    job.audit.egress = egress_records(&super::lock(&egress));
    report(
        shared,
        job,
        code,
        started,
        outcome.as_ref(),
        &writer,
        &flags,
    );
    let _ = s.shutdown(std::net::Shutdown::Both);
}

/// Start this run's custody proxy; the credentials move out of the job into it.
fn start_proxy(
    shared: &Arc<Shared>,
    job: &mut Job,
    egress: &Arc<Mutex<Vec<super::proxy::Outcome>>>,
) -> Result<super::proxy::Proxy, Error> {
    let token = crypto::random_hex::<16>().map_err(|_| Error::Internal(151))?;
    let connect = super::proxy::connector(&shared.dirs.state).map_err(|_| Error::Internal(152))?;
    let sink = egress.clone();
    let report: Arc<super::proxy::Report> = Arc::new(move |o| super::lock(&sink).push(o));
    let sh = shared.clone();
    let check: Arc<super::proxy::Check> =
        Arc::new(move |handle: &str, host: &str| super::server::check_host(&sh, handle, host));
    super::proxy::start(
        token,
        std::mem::take(&mut job.custody),
        job.redactor.clone(),
        connect,
        report,
        Some(check),
    )
    .map_err(|_| Error::Internal(153))
}

/// One audit record per (decision, host, handles) with its request count (ADR 0022; per-request records in ADR 0018).
fn egress_records(outcomes: &[super::proxy::Outcome]) -> Vec<crate::vault::audit::Record<'static>> {
    use super::proxy::Outcome;
    let mut out: Vec<crate::vault::audit::Record<'static>> = Vec::new();
    for o in outcomes {
        let (decision, host, handles): (&'static str, Option<String>, Vec<String>) = match o {
            Outcome::Forwarded { host, handles } => {
                ("forwarded", Some(host.clone()), handles.clone())
            }
            Outcome::Refused {
                reason,
                handle,
                host,
            } => (reason, host.clone(), handle.iter().cloned().collect()),
        };
        if let Some(r) = out
            .iter_mut()
            .find(|r| r.decision == Some(decision) && r.host == host && r.handles == handles)
        {
            r.requests = Some(r.requests.unwrap_or(0).saturating_add(1));
            continue;
        }
        let mut r = crate::vault::audit::Record::new("egress");
        r.decision = Some(decision);
        r.host = host;
        r.handles = handles;
        r.requests = Some(1);
        out.push(r);
    }
    out
}
