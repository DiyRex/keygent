//! The broker (SPEC §5.4): the unsealed daemon and the only process that holds plaintext.
//!
//! Started by `keygent unseal` as `keygent broker` with a cleared env and one inherited pipe carrying the DEK
//! handoff. Invariants:
//! - Hardening first (no dumps / deny attach, `RLIMIT_CORE=0`, `mlockall` on Linux), then the locked arena: if
//!   secret memory can't be locked, the broker refuses to start.
//! - One broker per user: `broker.lock` is held for the broker's lifetime; the socket lives in a fixed owner-only dir.
//! - Fail closed: any vault reload/verification error seals. Sealing drops all state (secrets wipe themselves) and exits.
//! - No response carries a value (ADR 0012); logs carry events and numbers only.

pub mod clock;
pub mod custody;
pub mod endpoint;
pub mod grant;
pub mod limits;
pub mod log;
pub mod proxy;
pub mod run;
mod server;

use crate::crypto::{self, Dek};
use crate::error::{Error, Result};
use crate::platform::{self, arena, ipc};
use crate::proto::tags::handoff as h;
use crate::proto::tlv::{Decoder, Encoder, Endian};
use crate::vault::Vault;
use clock::{Deadline, SuspendWatch};
use log::{Level, Log};
use std::io::Read;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;
use zeroize::Zeroizing;

pub const MAX_HANDOFF: usize = 64 * 1024;
pub const DEFAULT_TTL: Duration = Duration::from_secs(8 * 3600);
const THREAD_STACK: usize = 128 * 1024;

/// What `unseal` hands to the broker over the pipe (little-endian TLV).
pub struct Handoff {
    pub dek: Dek,
    pub ttl: Duration,
    pub idle: Duration,
    pub log_level: u8,
    /// PATH captured at unseal, used to resolve executables (SPEC §5.5.2). Never the client's env at request time.
    pub path: String,
}

impl Handoff {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut e = Encoder::new(Endian::Little);
        let r = (|| {
            e.bytes(h::DEK, self.dek.expose())?;
            e.u32(
                h::TTL,
                u32::try_from(self.ttl.as_secs()).unwrap_or(u32::MAX),
            )?;
            e.u32(
                h::IDLE,
                u32::try_from(self.idle.as_secs()).unwrap_or(u32::MAX),
            )?;
            e.u8(h::LOG_LEVEL, self.log_level)?;
            e.utf8(h::PATH, &self.path)
        })();
        r.map_err(|_| Error::Internal(110))?;
        Ok(e.finish())
    }

    pub fn decode(b: &[u8]) -> Result<Handoff> {
        let bad = |_| Error::Internal(111);
        let mut d = Decoder::new(b, Endian::Little).map_err(bad)?;
        let v = d.req(h::DEK).map_err(bad)?;
        let dek = Dek::from_bytes(d.as_array(h::DEK, v).map_err(bad)?);
        let v = d.req(h::TTL).map_err(bad)?;
        let ttl = Duration::from_secs(u64::from(d.as_u32(h::TTL, v).map_err(bad)?));
        let v = d.req(h::IDLE).map_err(bad)?;
        let idle = Duration::from_secs(u64::from(d.as_u32(h::IDLE, v).map_err(bad)?));
        let v = d.req(h::LOG_LEVEL).map_err(bad)?;
        let log_level = d.as_u8(h::LOG_LEVEL, v).map_err(bad)?;
        let v = d.req(h::PATH).map_err(bad)?;
        let path = d.as_str(h::PATH, v).map_err(bad)?.to_owned();
        d.finish().map_err(bad)?;
        if ttl.is_zero() || ttl > Duration::from_secs(24 * 3600) || idle.is_zero() {
            return Err(Error::Internal(112));
        }
        Ok(Handoff {
            dek,
            ttl,
            idle,
            log_level,
            path,
        })
    }
}

/// Mutable broker state behind one mutex. Never held across socket I/O.
pub struct State {
    pub vault: Vault,
    pub idle_deadline: Deadline,
    /// Every value seen this session (current, previous, and values since rotated away): the redactor keeps old
    /// values until seal (SPEC §5.7.5). Locked arena.
    pub registered: Vec<(String, crate::crypto::Secret)>,
    /// Shared with running jobs, which keep the snapshot they started with.
    pub redactor: Arc<crate::redact::Redactor>,
    pub grants: Vec<grant::Grant>,
}

impl State {
    /// Append one audit record (SPEC §9). Errors are fail-closed for the caller.
    pub fn audit(&self, dirs: &platform::Dirs, r: &crate::vault::audit::Record<'_>) -> Result<()> {
        let k = self.vault.audit_key()?;
        crate::vault::audit::append(dirs, &k, r).map(|_| ())
    }

    /// The audit record of a grant (command template redacted, pins and scripts by hash).
    pub fn grant_record<'a>(
        &self,
        g: &grant::Grant,
        event: &'a str,
        decision: &'a str,
    ) -> crate::vault::audit::Record<'a> {
        let mut r = crate::vault::audit::Record::new(event);
        r.handles = g.handles.clone();
        r.decision = Some(decision);
        r.cmd = Some(
            String::from_utf8_lossy(&self.redactor.redact_all(g.command.as_bytes()).0).into_owned(),
        );
        r.grant_key = Some(g.key);
        r.exes = g
            .programs
            .iter()
            .filter_map(|p| match p {
                crate::policy::resolve::Program::File { path, sha256 } => {
                    Some((path.display().to_string(), *sha256))
                }
                _ => None,
            })
            .collect();
        r.scripts = g
            .scripts
            .iter()
            .map(|s| {
                (
                    s.path.display().to_string(),
                    s.sha256,
                    u64::try_from(s.content.len()).unwrap_or(u64::MAX),
                )
            })
            .collect();
        r.cwd = Some(g.cwd.display().to_string());
        r
    }

    /// Register current + previous values of every handle, then (re)build the redactor. Any failure → caller seals.
    pub fn refresh_redactor(&mut self) -> std::result::Result<(), &'static str> {
        for r in &self.vault.index.handles {
            let cur = self
                .vault
                .read_entry(&r.handle)
                .map_err(|_| "seal_entry_unreadable")?;
            for v in std::iter::once(cur).chain(
                r.previous_value
                    .as_ref()
                    .map(|p| crate::crypto::Secret::from_slice(p.expose())),
            ) {
                if !self
                    .registered
                    .iter()
                    .any(|(h, s)| h == &r.handle && s.ct_eq(v.expose()))
                {
                    self.registered.push((r.handle.clone(), v));
                }
            }
        }
        self.redactor = Arc::new(
            crate::redact::Redactor::new(
                self.registered
                    .iter()
                    .map(|(h, s)| (h.as_str(), s.expose())),
            )
            .map_err(|_| "seal_redactor_too_large")?,
        );
        Ok(())
    }
}

pub struct Shared {
    pub state: Mutex<Option<State>>,
    pub dirs: platform::Dirs,
    pub log: Log,
    pub ttl: Deadline,
    pub idle: Duration,
    pub hardening: ipc::Hardening,
    pub build_id: String,
    /// PATH captured at unseal: executable resolution and the child's PATH (SPEC §5.5.2).
    pub path: String,
    pub sock: std::path::PathBuf,
    /// Signalled (with `state`) whenever a grant is approved or denied.
    pub decided: Condvar,
    /// Session ids of active runs; sealing kills them.
    pub runs: Mutex<Vec<i32>>,
    /// Connection, run, `Redact` and auth-failure limits (SPEC §4.1).
    pub limits: Limits,
    sealing: AtomicBool,
    /// A seal requested while the state lock is held (`write_vault`). Every later state-lock holder sees it
    /// (`lock_state`) and seals first, so nothing can use the state in between; first reason wins.
    deferred_seal: OnceLock<&'static str>,
}

/// The broker's limits (SPEC §4.1).
pub struct Limits {
    /// All connections (cap `server::MAX_CONNS`).
    pub conns: limits::Counter,
    /// Connections outside the reserved auth/control pool.
    pub general: limits::Counter,
    /// Concurrent runs (cap `run::MAX_RUNS`).
    pub runs: limits::Counter,
    /// `Redact`: 64 MiB/s global.
    pub redact: limits::ByteBucket,
    /// Failed auth proofs: 30 per minute, then `RateLimited`.
    pub auth_fails: limits::Window,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            conns: limits::Counter::default(),
            general: limits::Counter::default(),
            runs: limits::Counter::default(),
            redact: limits::ByteBucket::new(64 * 1024 * 1024),
            auth_fails: limits::Window::new(30, Duration::from_secs(60)),
        }
    }
}

/// Lock without poison handling: the release profile is `panic = "abort"`, so a poisoned lock can't be observed there,
/// and in tests the data is still the best state we have.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Shared {
    /// Request a seal from code that holds the state lock; returns the error to propagate.
    fn defer_seal(&self, reason: &'static str) -> Error {
        let _ = self.deferred_seal.set(reason);
        Error::Internal(156)
    }

    /// Seal now if a seal was deferred. Call only without the state lock held.
    pub fn seal_if_deferred(&self) {
        if let Some(r) = self.deferred_seal.get() {
            self.seal(r);
        }
    }

    /// Has a seal been deferred (and not yet performed)?
    pub fn is_seal_pending(&self) -> bool {
        self.deferred_seal.get().is_some()
    }

    /// Is a seal under way? A run registered after the seal copied the run list must kill itself.
    pub fn is_sealing(&self) -> bool {
        self.sealing.load(Ordering::SeqCst)
    }

    /// The state lock, but never handed out once a seal was deferred: the would-be holder seals instead (review fix:
    /// a waiter could otherwise take the lock between `defer_seal` and `seal_if_deferred` and act on an inconsistent
    /// vault). `None` when sealed.
    pub fn lock_state(&self) -> Option<MutexGuard<'_, Option<State>>> {
        let g = lock(&self.state);
        if self.deferred_seal.get().is_some() {
            drop(g);
            self.seal_if_deferred();
            return None;
        }
        if g.is_none() {
            return None;
        }
        Some(g)
    }

    /// Seal: drop every secret (locked blocks wipe themselves), remove the socket, exit. Runs once.
    pub fn seal(&self, reason: &'static str) -> ! {
        if self.sealing.swap(true, Ordering::SeqCst) {
            // another thread is already sealing; wait for it to exit the process
            loop {
                std::thread::park();
            }
        }
        self.log.event(Level::Info, reason, None);
        let _ = std::fs::remove_file(&self.sock);
        // the runs list is only ever held for a push/retain (never across a seal), so waiting is safe; every active
        // run must die with the session (review fix: `try_lock` could skip them)
        let sids: Vec<i32> = lock(&self.runs).clone();
        for sid in sids {
            ipc::kill_session(sid);
        }
        // never block here: a caller may (wrongly) still hold the lock; exiting frees everything regardless
        if let Ok(mut g) = self.state.try_lock() {
            if let Some(st) = g.as_ref() {
                // best effort: sealing never waits on, or is blocked by, the audit log
                let mut r = crate::vault::audit::Record::new("seal");
                r.decision = Some(reason);
                let _ = st.audit(&self.dirs, &r);
            }
            drop(g.take());
        }
        std::process::exit(0)
    }

    /// Broker-side vault write (ADR 0015), only for changes an agent may trigger: capability-reducing (`untrust`) or
    /// create-only (`capture`). Takes the vault lock without waiting, reloads, applies `f`, appends the audit record,
    /// anchors it in the index and commits. Any failure leaves the vault as it was on disk; a failed commit seals.
    pub fn write_vault(
        &self,
        st: &mut State,
        record: &crate::vault::audit::Record<'_>,
        f: impl FnOnce(&mut Vault) -> Result<crate::vault::Prev>,
    ) -> Result<()> {
        let _lock = crate::vault::try_lock(&self.dirs)?;
        if let Err(reason) = self.reload_if_changed(st) {
            return Err(self.defer_seal(reason));
        }
        // audit first (as the CLI does): no record, no change
        let k = st.vault.audit_key()?;
        let (seq, mac) = crate::vault::audit::append(&self.dirs, &k, record)?;
        let prev = match f(&mut st.vault) {
            Ok(p) => p,
            Err(e) => {
                // discard any partial in-memory change by reopening what is on disk
                return match Vault::open_with_dek(&self.dirs, st.vault.dek_copy()) {
                    Ok(v) => {
                        st.vault = v;
                        Err(e)
                    }
                    Err(_) => Err(self.defer_seal("seal_reload_failed")),
                };
            }
        };
        st.vault.index.audit_anchor = Some(crate::vault::index::AuditAnchor { seq, mac });
        if st.vault.commit(prev).is_err() {
            // memory and disk may now disagree: fail closed
            return Err(self.defer_seal("seal_commit_failed"));
        }
        st.refresh_redactor()
            .map_err(|reason| self.defer_seal(reason))
    }

    /// A client request counts as activity for the idle timer.
    pub fn touch(&self, st: &mut State) {
        st.idle_deadline = Deadline::after(self.idle);
    }

    /// Fail-closed reload: if the vault on disk moved to another generation (a CLI write, ADR 0012), reopen it with
    /// our DEK and re-verify the header MAC. On error the caller must release the state lock and `seal(reason)`.
    pub fn reload_if_changed(&self, st: &mut State) -> std::result::Result<(), &'static str> {
        match Vault::generation_on_disk(&self.dirs) {
            Ok(g) if g == st.vault.file.generation => Ok(()),
            Ok(_) => match Vault::open_with_dek(&self.dirs, st.vault.dek_copy()) {
                Ok(v) => {
                    st.vault = v;
                    st.refresh_redactor()?;
                    self.log.event(Level::Info, "vault_reloaded", None);
                    Ok(())
                }
                Err(_) => Err("seal_reload_failed"),
            },
            Err(_) => Err("seal_vault_unreadable"),
        }
    }
}

/// Arena sized for every value plus previous values, with headroom; ≥ 1 MiB.
fn arena_size(vault_file_len: u64) -> usize {
    usize::try_from(vault_file_len)
        .unwrap_or(usize::MAX)
        .saturating_mul(2)
        .saturating_add(1024 * 1024)
}

/// `keygent broker` (internal). Exit codes: 0 sealed normally or another broker already runs; 1 startup refused.
pub fn main() -> ExitCode {
    ipc::block_term_signals();
    let hardening = ipc::harden_broker();
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_HANDOFF.saturating_add(1)));
    if std::io::stdin()
        .lock()
        .take(u64::try_from(MAX_HANDOFF).unwrap_or(0).saturating_add(1))
        .read_to_end(&mut raw)
        .is_err()
        || raw.is_empty()
        || raw.len() > MAX_HANDOFF
    {
        return ExitCode::from(64);
    }
    let Ok(dirs) = platform::dirs() else {
        return ExitCode::from(1);
    };
    {
        use platform::Platform;
        let os = platform::os();
        if os.ensure_private_dir(&dirs.state).is_err() || os.ensure_private_dir(&dirs.run).is_err()
        {
            return ExitCode::from(1);
        }
    }
    let log_file_level;
    let handoff = match Handoff::decode(&raw) {
        Ok(h) => {
            log_file_level = Level::from_u8(h.log_level);
            h
        }
        Err(_) => return ExitCode::from(64),
    };
    drop(raw);
    let log = Log::open(&dirs.state, log_file_level);
    // the locked arena comes before any secret is materialised from the vault
    let vault_len = std::fs::metadata(Vault::path(&dirs))
        .map(|m| m.len())
        .unwrap_or(0);
    if arena::init(arena_size(vault_len)).is_err() {
        log.event(Level::Error, "refuse_start_memlock", None);
        return ExitCode::from(1);
    }
    let dek = Dek::from_bytes(*handoff.dek.expose());
    drop(handoff.dek);
    let endpoint = match endpoint::bind(&dirs.run) {
        Ok(Some(e)) => e,
        Ok(None) => {
            log.event(Level::Info, "already_running", None);
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            log.event(Level::Error, "refuse_start_endpoint", None);
            return ExitCode::from(1);
        }
    };
    let vault = match Vault::open_with_dek(&dirs, dek) {
        Ok(v) => v,
        Err(_) => {
            log.event(Level::Error, "refuse_start_vault", None);
            let _ = std::fs::remove_file(&endpoint.sock);
            return ExitCode::from(1);
        }
    };
    run::sweep_bindings(&dirs.run);
    log.event(
        Level::Info,
        "unsealed",
        Some(u64::from(
            u32::try_from(vault.index.handles.len()).unwrap_or(0),
        )),
    );
    let mut state = State {
        vault,
        idle_deadline: Deadline::after(handoff.idle),
        registered: Vec::new(),
        redactor: match crate::redact::Redactor::new(std::iter::empty()) {
            Ok(r) => Arc::new(r),
            Err(_) => return ExitCode::from(1),
        },
        grants: Vec::new(),
    };
    // SPEC §5.8: unseal refuses a vault whose secrets exceed the redactor cap
    if let Err(reason) = state.refresh_redactor() {
        log.event(Level::Error, reason, None);
        let _ = std::fs::remove_file(&endpoint.sock);
        return ExitCode::from(1);
    }
    // fail closed: no session starts without a writable audit log
    if state
        .audit(&dirs, &crate::vault::audit::Record::new("unseal"))
        .is_err()
    {
        log.event(Level::Error, "refuse_start_audit", None);
        let _ = std::fs::remove_file(&endpoint.sock);
        return ExitCode::from(1);
    }
    let shared = Arc::new(Shared {
        state: Mutex::new(Some(state)),
        dirs,
        log,
        ttl: Deadline::after(handoff.ttl),
        idle: handoff.idle,
        hardening,
        build_id: crate::cli::build_id(),
        path: handoff.path,
        sock: endpoint.sock.clone(),
        decided: Condvar::new(),
        runs: Mutex::new(Vec::new()),
        sealing: AtomicBool::new(false),
        deferred_seal: OnceLock::new(),
        limits: Limits::default(),
    });
    // the TTL / idle / wake / signal watchers are what seal the session: no watchers, no session (fail closed)
    if !spawn_watchers(&shared) {
        // startup refused (exit 1, per this function's contract); dropping `shared` wipes the state
        shared
            .log
            .event(Level::Error, "refuse_start_watchers", None);
        let _ = std::fs::remove_file(&endpoint.sock);
        return ExitCode::from(1);
    }
    server::serve(&shared, &endpoint.listener);
    shared.seal("seal_listener_closed")
}

fn spawn_watchers(shared: &Arc<Shared>) -> bool {
    let s = shared.clone();
    let signals = std::thread::Builder::new()
        .stack_size(THREAD_STACK)
        .spawn(move || {
            let _sig = ipc::wait_term_signal();
            s.seal("seal_signal")
        });
    let s = shared.clone();
    let timers = std::thread::Builder::new()
        .stack_size(THREAD_STACK)
        .spawn(move || {
            let mut watch = SuspendWatch::new();
            loop {
                std::thread::sleep(Duration::from_secs(1));
                // backstop for a seal deferred under the state lock
                s.seal_if_deferred();
                if s.ttl.expired() {
                    s.seal("seal_ttl");
                }
                if watch.suspended_longer_than(s.idle) {
                    s.seal("seal_wake");
                }
                // an active run is activity: it keeps the idle timer from firing (the TTL still applies)
                let running = !lock(&s.runs).is_empty();
                let idle_expired = lock(&s.state).as_mut().map(|st| {
                    if running {
                        st.idle_deadline = Deadline::after(s.idle);
                    }
                    st.idle_deadline.expired()
                });
                if idle_expired != Some(false) {
                    s.seal("seal_idle");
                }
            }
        });
    signals.is_ok() && timers.is_ok()
}

/// Verify the broker's handshake proof with keys the CLI derived locally (auth flows; SPEC §5.5.1).
pub fn expected_proof(dek: &Dek, uuid: &[u8; 16], nc: &[u8], nb: &[u8]) -> Result<[u8; 32]> {
    let kb = crypto::subkey(uuid, dek, crypto::label::BROKER)?;
    crypto::proof_broker(&kb, nc, nb)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    #[test]
    fn handoff_roundtrip_and_limits() {
        let h = Handoff {
            dek: Dek::from_bytes([4; 32]),
            ttl: Duration::from_secs(60),
            idle: Duration::from_secs(30),
            log_level: 2,
            path: "/usr/bin:/bin".into(),
        };
        let b = h.encode().unwrap();
        let d = Handoff::decode(&b).unwrap();
        assert_eq!(
            (d.dek.expose(), d.ttl, d.idle, d.path.as_str()),
            (&[4; 32], h.ttl, h.idle, "/usr/bin:/bin")
        );
        let long = Handoff {
            ttl: Duration::from_secs(25 * 3600),
            ..h
        };
        assert!(
            Handoff::decode(&long.encode().unwrap()).is_err(),
            "TTL above 24 h refused"
        );
        assert!(Handoff::decode(&b[..b.len() - 1]).is_err());
    }
}
