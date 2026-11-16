//! Connection handling (ADR 0004): peer-uid check, connection caps with a reserved pool, `Hello`/`Welcome`
//! handshake with the broker proof, then one request per connection. Timeouts: 5 s for the first frame, 30 s idle.
//! Errors never echo request contents.

use super::{Shared, log::Level};
use crate::crypto;
use crate::platform::ipc;
use crate::proto::frame::{self, ty};
use crate::proto::msg::{self, Class, ErrMsg, Hello, ListEntry, StatusReply, Welcome, code};
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
    match req.ty {
        ty::STATUS if msg::expect_empty(&req.payload).is_ok() => status(shared, &mut s),
        ty::LIST if msg::expect_empty(&req.payload).is_ok() => list(shared, &mut s),
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
