//! Connection handling (ADR 0004): peer-uid check, connection caps with a reserved pool, `Hello`/`Welcome`
//! handshake with the broker proof, then one request per connection. Timeouts: 5 s for the first frame, 30 s idle.
//! Errors never echo request contents.

use super::grant::{self, State as GState};
use super::{Shared, log::Level, run};
use crate::crypto;
use crate::error::{Error, PolicyMsg};
use crate::platform::ipc;
use crate::proto::frame::{self, ty};
use crate::proto::msg::{
    self, Approve, Class, ErrMsg, GrantCreate, Hello, ListEntry, PendingGrant, StatusReply,
    Welcome, code, gstate,
};
use crate::vault::index::Mode;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub const MAX_CONNS: usize = 32;
/// Reserved for `auth`/`control` (4) and hook `MatchPrompt` (1) (SPEC §4.1).
pub const RESERVED: usize = 5;
const FIRST_FRAME: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(30);

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static GENERAL: AtomicUsize = AtomicUsize::new(0);

struct Slot(&'static AtomicUsize);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn take(counter: &'static AtomicUsize, cap: usize) -> Option<Slot> {
    let prev = counter.fetch_add(1, Ordering::SeqCst);
    if prev >= cap {
        counter.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(Slot(counter))
}

pub fn serve(shared: &Arc<Shared>, listener: &UnixListener) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        // other users never get past accept (SPEC §5.4; the dir is 0700 as well)
        match ipc::peer_cred(&stream) {
            Ok((uid, _)) if uid == ipc::uid() => {}
            _ => continue,
        }
        let Some(slot) = take(&ACTIVE, MAX_CONNS) else {
            continue;
        };
        let s = shared.clone();
        let spawned = std::thread::Builder::new()
            .stack_size(super::THREAD_STACK)
            .spawn(move || {
                let _slot = slot;
                handle(&s, stream);
            });
        if spawned.is_err() {
            shared.log.event(Level::Warn, "thread_spawn_failed", None);
        }
    }
}

fn send_err(s: &mut UnixStream, code: u16, message: &str) {
    if let Ok(p) = (ErrMsg {
        code,
        message: message.to_owned(),
    })
    .encode()
    {
        let _ = frame::write(s, ty::ERR, &p);
    }
}

/// Send a canonical `keygent:` error line with the protocol code its exit code maps to (ERRORS.md).
pub fn send_error(s: &mut UnixStream, e: &Error) {
    let c = match e {
        Error::RateLimited => code::RATE_LIMITED,
        Error::TooLarge(_) => code::TOO_LARGE,
        Error::Sealed => code::SEALED,
        Error::AuditUnwritable | Error::AuditBroken(_) => code::AUDIT,
        _ => match e.exit_code() {
            crate::error::exit::APPROVAL => code::APPROVAL_DENIED,
            crate::error::exit::NOT_TRUSTED => code::NOT_TRUSTED,
            crate::error::exit::POLICY => code::POLICY_DENIED,
            crate::error::exit::RUN_LIMIT => code::RUN_LIMIT,
            crate::error::exit::USAGE => code::BAD_REQUEST,
            _ => code::INTERNAL,
        },
    };
    send_err(s, c, &e.to_string());
}

fn bad_request(s: &mut UnixStream) {
    send_err(
        s,
        code::BAD_REQUEST,
        "keygent: broker error 10 — run 'keygent doctor'",
    );
}

fn handle(shared: &Shared, mut s: UnixStream) {
    let _ = s.set_read_timeout(Some(FIRST_FRAME));
    let _ = s.set_write_timeout(Some(IDLE));
    let Ok(f) = frame::read(&mut s) else { return };
    if f.ty != ty::HELLO {
        return;
    }
    let Ok(hello) = Hello::decode(&f.payload) else {
        return;
    };
    // the reserved pool: only auth/control may use the last RESERVED slots
    let _general = match hello.class {
        Class::Auth | Class::Control => None,
        _ => match take(&GENERAL, MAX_CONNS.saturating_sub(RESERVED)) {
            Some(g) => Some(g),
            None => {
                send_err(
                    &mut s,
                    code::RATE_LIMITED,
                    "keygent: too many requests — retry in a few seconds",
                );
                return;
            }
        },
    };
    if hello.build_id != shared.build_id {
        send_err(
            &mut s,
            code::VERSION_MISMATCH,
            "keygent: updated — run 'keygent seal' then 'keygent unseal'",
        );
        return;
    }
    let Ok(nb) = crypto::random::<{ msg::NONCE_LEN }>() else {
        return;
    };
    let proof = {
        let Ok(g) = shared.state.lock() else { return };
        let Some(st) = g.as_ref() else { return };
        match st.vault.broker_proof(&hello.nonce, &nb) {
            Ok(p) => p,
            Err(_) => return,
        }
    };
    let Ok(w) = (Welcome {
        build_id: shared.build_id.clone(),
        nonce: nb,
        proof,
    })
    .encode() else {
        return;
    };
    if frame::write(&mut s, ty::WELCOME, &w).is_err() {
        return;
    }
    let _ = s.set_read_timeout(Some(IDLE));
    let Ok(req) = frame::read(&mut s) else { return };
    if shared.ttl.expired() {
        shared.seal("seal_ttl");
    }
    // `control` is limited to Seal/Status/Deny (SPEC §4.1)
    if hello.class == Class::Control && !matches!(req.ty, ty::SEAL | ty::STATUS | ty::DENY) {
        bad_request(&mut s);
        return;
    }
    match req.ty {
        ty::GRANT_CREATE => grant_create(shared, &mut s, &req.payload),
        ty::AWAIT_GRANT => await_grant(shared, &mut s, &req.payload),
        ty::PENDING if msg::expect_empty(&req.payload).is_ok() => pending(shared, &mut s),
        ty::APPROVE => approve(shared, &mut s, &req.payload, &nb, &hello.nonce),
        ty::DENY => deny(shared, &mut s, &req.payload),
        ty::UNTRUST => untrust(shared, &mut s, &req.payload),
        ty::AUDIT_VERIFY if msg::expect_empty(&req.payload).is_ok() => audit_verify(shared, &mut s),
        ty::RUN => run_grant(shared, s, &req.payload),
        ty::STATUS if msg::expect_empty(&req.payload).is_ok() => status(shared, &mut s),
        ty::LIST if msg::expect_empty(&req.payload).is_ok() => list(shared, &mut s),
        ty::REDACT => redact(shared, &mut s, &req.payload),
        ty::SEAL if msg::expect_empty(&req.payload).is_ok() => {
            let _ = frame::write(&mut s, ty::OK, &[]);
            drop(s);
            shared.seal("seal_requested")
        }
        _ => send_err(
            &mut s,
            code::BAD_REQUEST,
            "keygent: broker error 10 — run 'keygent doctor'",
        ),
    }
}

fn status(shared: &Shared, s: &mut UnixStream) {
    let reply = {
        let Ok(g) = shared.state.lock() else { return };
        let Some(st) = g.as_ref() else { return };
        StatusReply {
            pid: std::process::id(),
            ttl_left_secs: shared.ttl.remaining().as_secs(),
            idle_left_secs: st.idle_deadline.remaining().as_secs(),
            handles: u32::try_from(st.vault.index.handles.len()).unwrap_or(u32::MAX),
            no_dumps: shared.hardening.no_dumps && !crypto::arena_overflowed(),
            mlockall: shared.hardening.mlockall,
        }
    };
    if let Ok(p) = reply.encode() {
        let _ = frame::write(s, ty::STATUS_REPLY, &p);
    }
}

fn list(shared: &Shared, s: &mut UnixStream) {
    let entries: Vec<ListEntry> = {
        let Ok(mut g) = shared.state.lock() else {
            return;
        };
        let Some(st) = g.as_mut() else { return };
        if let Err(reason) = shared.reload_if_changed(st) {
            drop(g);
            shared.seal(reason);
        }
        st.vault
            .index
            .handles
            .iter()
            .map(|r| ListEntry {
                handle: r.handle.clone(),
                env_name: r.env_name.clone(),
                mode: r.mode as u8,
                binding: r.binding as u8,
                exposed: r.exposed,
                description: r.description.clone(),
            })
            .collect()
    };
    match msg::encode_list(&entries) {
        Ok(p) => {
            let _ = frame::write(s, ty::LIST_REPLY, &p);
        }
        Err(_) => send_err(s, code::TOO_LARGE, "keygent: input too large (limit 1 MiB)"),
    }
}

/// Global `Redact` budget: 64 MiB/s (SPEC §4.1). A `Redact` hit inherently confirms a candidate value; the 80-bit
/// strength floor is the defense, the rate limit only bounds guessing throughput (THREATS known gap).
const REDACT_BYTES_PER_SEC: f64 = 64.0 * 1024.0 * 1024.0;
static REDACT_BUCKET: std::sync::Mutex<Option<(std::time::Instant, f64)>> =
    std::sync::Mutex::new(None);

fn redact_budget(n: usize) -> bool {
    let Ok(mut g) = REDACT_BUCKET.lock() else {
        return false;
    };
    let now = std::time::Instant::now();
    let (last, tokens) = g.unwrap_or((now, REDACT_BYTES_PER_SEC));
    #[allow(clippy::cast_precision_loss)]
    let refill = (tokens + now.duration_since(last).as_secs_f64() * REDACT_BYTES_PER_SEC)
        .min(REDACT_BYTES_PER_SEC);
    #[allow(clippy::cast_precision_loss)]
    let need = n as f64;
    if refill < need {
        *g = Some((now, refill));
        return false;
    }
    *g = Some((now, refill - need));
    true
}

fn redact(shared: &Shared, s: &mut UnixStream, payload: &[u8]) {
    let Ok((data, _)) = msg::decode_data(payload, false) else {
        send_err(
            s,
            code::BAD_REQUEST,
            "keygent: broker error 10 — run 'keygent doctor'",
        );
        return;
    };
    if !redact_budget(data.len()) {
        send_err(
            s,
            code::RATE_LIMITED,
            "keygent: too many requests — retry in a few seconds",
        );
        return;
    }
    let (out, hits) = {
        let Ok(mut g) = shared.state.lock() else {
            return;
        };
        let Some(st) = g.as_mut() else { return };
        if let Err(reason) = shared.reload_if_changed(st) {
            drop(g);
            shared.seal(reason);
        }
        st.redactor.redact_all(&data)
    };
    match msg::encode_data(&out, Some(u32::try_from(hits).unwrap_or(u32::MAX))) {
        Ok(p) => {
            let _ = frame::write(s, ty::REDACTED, &p);
        }
        Err(_) => send_err(s, code::TOO_LARGE, "keygent: input too large (limit 1 MiB)"),
    }
}

// ---------------------------------------------------------------- grants (SPEC §5.5.2)

/// Lock the state, reload if the vault changed (sealing on failure), and run `f`. `None` when sealed.
fn with_state<T>(shared: &Shared, f: impl FnOnce(&mut super::State) -> T) -> Option<T> {
    let mut g = shared.state.lock().ok()?;
    let st = g.as_mut()?;
    if let Err(reason) = shared.reload_if_changed(st) {
        drop(g);
        shared.seal(reason);
    }
    shared.touch(st);
    Some(f(st))
}

fn wire_state(g: &grant::Grant) -> u8 {
    match g.state {
        GState::Pending => gstate::PENDING,
        GState::Approved => gstate::APPROVED,
        GState::Denied => gstate::DENIED,
        GState::Consumed => gstate::EXPIRED,
    }
}

fn first_handle(g: &grant::Grant) -> String {
    g.handles
        .first()
        .cloned()
        .unwrap_or_else(|| "this command".into())
}

fn grant_create(shared: &Shared, s: &mut UnixStream, payload: &[u8]) {
    let Ok(gc) = GrantCreate::decode(payload) else {
        return bad_request(s);
    };
    let Some((snap, trusted)) = with_state(shared, |st| {
        (
            grant::policy_snapshot(&st.vault.index),
            st.vault
                .index
                .trusted_manifests
                .iter()
                .map(|t| (t.canonical_path.clone(), t.sha256))
                .collect::<Vec<_>>(),
        )
    }) else {
        return;
    };
    // resolution and hashing happen without the state lock
    let home = run::user_home();
    let built = grant::build(
        &grant::Request {
            command: &gc.cmd,
            cwd: &gc.cwd,
            max_runtime: gc.max_runtime_secs.map(std::time::Duration::from_secs),
        },
        &snap,
        &trusted,
        &shared.path,
        home.as_deref(),
    );
    let g = match built {
        Ok(g) => g,
        Err(e) => return send_error(s, &e),
    };
    let r = with_state(shared, |st| {
        let decision = if g.state == GState::Approved {
            "auto"
        } else {
            "pending"
        };
        st.audit(&shared.dirs, &st.grant_record(&g, "grant", decision))?;
        let id = grant::insert(&mut st.grants, g)?;
        let state = grant::find(&mut st.grants, &id).map_or(gstate::EXPIRED, |x| wire_state(x));
        Ok::<_, Error>((id, state))
    });
    match r {
        Some(Ok((id, state))) => {
            shared.log.event(Level::Info, "grant_created", None);
            match msg::encode_grant(&id, Some(state)) {
                Ok(p) => {
                    let _ = frame::write(s, ty::GRANT_CREATED, &p);
                }
                Err(_) => bad_request(s),
            }
        }
        Some(Err(e)) => send_error(s, &e),
        None => {}
    }
}

/// Blocks until the grant is decided or ages out of the queue (SPEC §4.1 "Approval wait").
fn await_grant(shared: &Shared, s: &mut UnixStream, payload: &[u8]) {
    let Ok((id, _)) = msg::decode_grant(payload, false) else {
        return bad_request(s);
    };
    let outcome: Result<(), Error> = {
        let Ok(mut g) = shared.state.lock() else {
            return;
        };
        loop {
            let Some(st) = g.as_mut() else { return };
            match grant::find(&mut st.grants, &id) {
                None => break Err(Error::Policy(PolicyMsg::QueueTimeout)),
                Some(x) if x.created.expired() => {
                    break Err(Error::Policy(PolicyMsg::QueueTimeout));
                }
                Some(x) => match x.state {
                    GState::Approved => break Ok(()),
                    GState::Denied | GState::Consumed => {
                        break Err(Error::Policy(PolicyMsg::Denied(first_handle(x))));
                    }
                    GState::Pending => {}
                },
            }
            g = match shared
                .decided
                .wait_timeout(g, std::time::Duration::from_secs(1))
            {
                Ok((g, _)) => g,
                Err(_) => return,
            };
        }
    };
    match outcome {
        Ok(()) => {
            if let Ok(p) = msg::encode_grant(&id, Some(gstate::APPROVED)) {
                let _ = frame::write(s, ty::GRANT_DECISION, &p);
            }
        }
        Err(e) => send_error(s, &e),
    }
}

fn pending(shared: &Shared, s: &mut UnixStream) {
    let Some(list) = with_state(shared, |st| {
        grant::prune(&mut st.grants);
        st.grants
            .iter()
            .filter(|g| g.state == GState::Pending)
            .map(|g| PendingGrant {
                id: g.id,
                key: g.key,
                unbound: g.unbound,
                rendered: g.rendered.clone(),
            })
            .collect::<Vec<_>>()
    }) else {
        return;
    };
    match msg::encode_pending(&list) {
        Ok(p) => {
            let _ = frame::write(s, ty::PENDING_REPLY, &p);
        }
        Err(_) => send_err(s, code::TOO_LARGE, "keygent: input too large (limit 1 MiB)"),
    }
}

/// Failed auth proofs in the current minute (SPEC §4.1 "Auth failure": 30/min, then `RateLimited`).
static AUTH_FAILS: std::sync::Mutex<Option<(std::time::Instant, u32)>> =
    std::sync::Mutex::new(None);
const AUTH_FAILS_PER_MIN: u32 = 30;

/// Count a failure; `false` once over the cap.
fn auth_failure() -> bool {
    let Ok(mut g) = AUTH_FAILS.lock() else {
        return false;
    };
    let now = std::time::Instant::now();
    let (start, n) = match *g {
        Some((t, n)) if now.duration_since(t) < std::time::Duration::from_secs(60) => (t, n),
        _ => (now, 0),
    };
    *g = Some((start, n.saturating_add(1)));
    n < AUTH_FAILS_PER_MIN
}

/// `Approve` needs `proof_c` over the request (grant id + the grant key the human saw), which only a holder of the
/// DEK — i.e. someone who just typed the passphrase — can compute. A correct proof is never delayed.
fn approve(shared: &Shared, s: &mut UnixStream, payload: &[u8], nb: &[u8], nc: &[u8]) {
    let Ok(a) = Approve::decode(payload) else {
        return bad_request(s);
    };
    let Ok(req) = a.request_bytes() else {
        return bad_request(s);
    };
    let Some(expected) = with_state(shared, |st| st.vault.auth_proof(nb, nc, &req)) else {
        return;
    };
    if !expected.is_ok_and(|e| crypto::verify_proof(&e, &a.proof)) {
        shared.log.event(Level::Warn, "auth_failed", None);
        let _ = with_state(shared, |st| {
            st.audit(&shared.dirs, &crate::vault::audit::Record::new("auth_fail"))
        });
        if auth_failure() {
            std::thread::sleep(std::time::Duration::from_secs(1));
            send_err(
                s,
                code::NEEDS_AUTH,
                "keygent: this needs your passphrase — run it in your own terminal",
            );
        } else {
            send_error(s, &Error::RateLimited);
        }
        return;
    }
    let r = with_state(shared, |st| {
        let pos = st
            .grants
            .iter()
            .position(|g| {
                crypto::ct_eq(&g.id, &a.id) && g.state == GState::Pending && !g.created.expired()
            })
            .ok_or(Error::Policy(PolicyMsg::QueueTimeout))?;
        let g = st.grants.get(pos).ok_or(Error::Internal(144))?;
        if !crypto::ct_eq(&g.key, &a.key) {
            return Err(Error::Policy(PolicyMsg::Changed));
        }
        if a.remember && g.unbound {
            return Err(Error::Policy(PolicyMsg::NoRemember));
        }
        let mut rec = st.grant_record(g, "approve", "approved");
        rec.channel = Some("terminal");
        st.audit(&shared.dirs, &rec)?;
        let g = st.grants.get_mut(pos).ok_or(Error::Internal(144))?;
        g.state = GState::Approved;
        // the approved grant waits for its run for at most another queue lifetime
        g.created = super::clock::Deadline::after(grant::QUEUE_LIFE);
        Ok(())
    });
    match r {
        Some(Ok(())) => {
            shared.decided.notify_all();
            shared.log.event(Level::Info, "grant_approved", None);
            let _ = frame::write(s, ty::OK, &[]);
        }
        Some(Err(e)) => send_error(s, &e),
        None => {}
    }
}

/// `Deny{id | all}`: no auth (it only removes capability). Unknown ids are not an error.
fn deny(shared: &Shared, s: &mut UnixStream, payload: &[u8]) {
    let Ok(target) = msg::decode_deny(payload) else {
        return bad_request(s);
    };
    let n = with_state(shared, |st| {
        let mut n = 0u64;
        let mut records = Vec::new();
        for g in st.grants.iter_mut().filter(|g| g.state == GState::Pending) {
            if target.is_none_or(|id| crypto::ct_eq(&g.id, &id)) {
                g.state = GState::Denied;
                n = n.saturating_add(1);
                records.push(g.id);
            }
        }
        // denial only removes capability, so a failed audit append doesn't undo it
        for id in records {
            if let Some(g) = st.grants.iter().find(|g| g.id == id) {
                let _ = st.audit(&shared.dirs, &st.grant_record(g, "deny", "denied"));
            }
        }
        n
    });
    if let Some(n) = n {
        shared.decided.notify_all();
        shared.log.event(Level::Info, "grant_denied", Some(n));
        let _ = frame::write(s, ty::OK, &[]);
    }
}

/// `Untrust{cwd}` (agent-safe, SPEC §5.1): drop the trust record of the manifest that governs `cwd`. Only removes
/// capability, so it needs no auth.
fn untrust(shared: &Shared, s: &mut UnixStream, payload: &[u8]) {
    let Ok(gc) = GrantCreate::decode(payload) else {
        return bad_request(s);
    };
    let Ok(cwd) = std::fs::canonicalize(&gc.cwd) else {
        return send_error(s, &Error::NoManifest);
    };
    let Some(m) = crate::policy::manifest::find(&cwd) else {
        return send_error(s, &Error::NoManifest);
    };
    let path = m.path.display().to_string();
    let r = with_state(shared, |st| {
        if !st
            .vault
            .index
            .trusted_manifests
            .iter()
            .any(|t| t.canonical_path == path)
        {
            return Ok(false);
        }
        let mut rec = crate::vault::audit::Record::new("untrust");
        rec.cwd = Some(path.clone());
        shared
            .write_vault(st, &rec, |v| {
                v.index
                    .trusted_manifests
                    .retain(|t| t.canonical_path != path);
                Ok(crate::vault::Prev::Keep)
            })
            .map(|()| true)
    });
    match r {
        Some(Ok(_)) => {
            let _ = frame::write(s, ty::OK, &[]);
        }
        Some(Err(e)) => send_error(s, &e),
        None => {}
    }
}

/// `AuditVerify`: check the whole chain, the anchor file and the index anchor with `K_audit` (SPEC §9).
fn audit_verify(shared: &Shared, s: &mut UnixStream) {
    let Some(r) = with_state(shared, |st| {
        let key = st.vault.audit_key()?;
        let anchor = st.vault.index.audit_anchor.as_ref().map(|a| (a.seq, a.mac));
        crate::vault::audit::verify(&shared.dirs, &key, anchor).map_err(Error::AuditBroken)
    }) else {
        return;
    };
    match r.and_then(|n| {
        msg::encode_u32(
            crate::proto::tags::proto::COUNT,
            u32::try_from(n).unwrap_or(u32::MAX),
        )
        .map_err(|_| Error::Internal(145))
    }) {
        Ok(p) => {
            let _ = frame::write(s, ty::AUDIT_OK, &p);
        }
        Err(e) => send_error(s, &e),
    }
}

/// `Run{grant_id}`: consume an approved grant and execute the command stored in it.
fn run_grant(shared: &Shared, mut s: UnixStream, payload: &[u8]) {
    let Ok((id, _)) = msg::decode_grant(payload, false) else {
        return bad_request(&mut s);
    };
    let Some(slot) = run::take_slot() else {
        return send_error(&mut s, &Error::RateLimited);
    };
    let job = with_state(shared, |st| {
        let pos = st
            .grants
            .iter()
            .position(|g| crypto::ct_eq(&g.id, &id))
            .ok_or(Error::Policy(PolicyMsg::QueueTimeout))?;
        let g = st.grants.get(pos).ok_or(Error::Internal(144))?;
        if g.created.expired() {
            return Err(Error::Policy(PolicyMsg::QueueTimeout));
        }
        if g.state != GState::Approved {
            return Err(Error::Policy(PolicyMsg::Denied(first_handle(g))));
        }
        // policy may have changed since approval (a handle denied or removed): re-check at use
        for h in &g.handles {
            match st.vault.index.get(h) {
                Some(r) if r.mode != Mode::Deny => {}
                _ => return Err(Error::Policy(PolicyMsg::NotAllowed(h.clone()))),
            }
        }
        let mut env_secrets = Vec::new();
        let mut file_secrets = Vec::new();
        for b in &g.bindings {
            let v = st
                .vault
                .read_entry(&b.handle)
                .map_err(|_| Error::Internal(143))?;
            if b.file {
                file_secrets.push((b.var.clone(), v));
            } else {
                env_secrets.push((b.var.clone(), v));
            }
        }
        // fail closed: no audit record, no run (SPEC §5.7 step 7)
        st.audit(&shared.dirs, &st.grant_record(g, "run", "start"))?;
        let job = run::Job {
            command: g.rewritten.clone(),
            cwd: g.cwd.clone(),
            env_secrets,
            file_secrets,
            scripts: g
                .scripts
                .iter()
                .map(|x| (x.var.clone(), x.content.clone()))
                .collect(),
            programs: g.programs.clone(),
            direct: match (&g.direct, g.programs.first()) {
                (Some(argv), Some(crate::policy::resolve::Program::File { path, sha256 })) => {
                    Some((path.clone(), *sha256, argv.clone()))
                }
                (Some(_), _) => return Err(Error::Internal(148)),
                (None, _) => None,
            },
            scratch: g.scratch,
            max_runtime: g.max_runtime,
            redactor: st.redactor.clone(),
            audit: (st.vault.audit_key()?, st.grant_record(g, "run", "end")),
        };
        if let Some(g) = st.grants.get_mut(pos) {
            g.state = GState::Consumed;
        }
        Ok(job)
    });
    match job {
        Some(Ok(job)) => {
            run::execute(shared, s, job);
            drop(slot);
        }
        Some(Err(e)) => send_error(&mut s, &e),
        None => {}
    }
}
