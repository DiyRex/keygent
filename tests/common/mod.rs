//! Shared helpers for the end-to-end tests (`cli.rs`, `leak.rs`): the real binary isolated under `KEYGENT_TEST_ROOT`
//! (test-profile feature), driven through its test console. Canaries only: `KEYGENT_CANARY_<random>`.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    reason = "test helpers: each test crate uses a subset; a panic is the failure report"
)]

use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const PASS: &str = "orbit-canyon-velvet-anchor-mosaic-tundra";
pub const PASS2: &str = "cherisher-fanciness-hurray-natural-refuse-truce";

pub fn rand_u64() -> u64 {
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

pub fn canary() -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::from("KEYGENT_CANARY_");
    let mut x = rand_u64() | 1;
    for _ in 0..24 {
        if x < 64 {
            x = rand_u64() | 1 << 63;
        }
        s.push(A[(x % 62) as usize] as char);
        x /= 62;
    }
    s
}

pub struct Root(pub PathBuf);
impl Root {
    pub fn new() -> Root {
        Self::under(&std::env::temp_dir())
    }
    pub fn under(dir: &Path) -> Root {
        let p = dir.join(format!("kg-cli-{:016x}", rand_u64()));
        std::fs::create_dir_all(&p).unwrap();
        Root(p)
    }
    pub fn data(&self) -> PathBuf {
        self.0.join("data")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        // never leave a broker running after a test (even a failed one)
        let _ = cmd(self, &["seal"]).stdin(Stdio::null()).output();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn cmd(root: &Root, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_keygent"));
    c.args(args)
        .env_clear()
        .env("KEYGENT_TEST_ROOT", &root.0)
        .env("KEYGENT_TEST_FAST_KDF", "1")
        .env("HOME", &root.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Minimal expect-style driver over the test console (stdin / stderr).
pub struct Session {
    pub child: Child,
    pub stdin: Option<ChildStdin>,
    pub err: Arc<Mutex<Vec<u8>>>,
    pub out: Arc<Mutex<Vec<u8>>>,
    pub seen: usize,
}

impl Session {
    pub fn start(root: &Root, args: &[&str]) -> Session {
        Self::start_cmd(cmd(root, args))
    }
    pub fn start_cmd(mut c: Command) -> Session {
        let mut child = c.spawn().unwrap();
        let stdin = child.stdin.take();
        let err = Arc::new(Mutex::new(Vec::new()));
        let out = Arc::new(Mutex::new(Vec::new()));
        for (src, buf) in [
            (
                child
                    .stderr
                    .take()
                    .map(|s| Box::new(s) as Box<dyn Read + Send>),
                err.clone(),
            ),
            (
                child
                    .stdout
                    .take()
                    .map(|s| Box::new(s) as Box<dyn Read + Send>),
                out.clone(),
            ),
        ] {
            let mut src = src.unwrap();
            std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                while let Ok(n) = src.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    buf.lock().unwrap().extend_from_slice(&b[..n]);
                }
            });
        }
        Session {
            child,
            stdin,
            err,
            out,
            seen: 0,
        }
    }
    /// Wait until `pat` appears in stderr after the last match; returns the text before it.
    pub fn expect(&mut self, pat: &str) -> String {
        let t = Instant::now();
        loop {
            {
                let e = self.err.lock().unwrap();
                let hay = &e[self.seen..];
                if let Some(i) = hay.windows(pat.len()).position(|w| w == pat.as_bytes()) {
                    let before = String::from_utf8_lossy(&hay[..i]).into_owned();
                    self.seen += i + pat.len();
                    return before;
                }
            }
            if t.elapsed() > Duration::from_secs(20) {
                panic!(
                    "timeout waiting for {pat:?}; stderr so far: {}",
                    String::from_utf8_lossy(&self.err.lock().unwrap())
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn send(&mut self, line: &str) {
        // the child may already have exited (an error before all answers were read)
        let s = self.stdin.as_mut().unwrap();
        let _ = s
            .write_all(line.as_bytes())
            .and_then(|()| s.write_all(b"\n"))
            .and_then(|()| s.flush());
    }
    pub fn finish(mut self) -> (i32, String, String) {
        drop(self.stdin.take());
        let st = self.child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let out = String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned();
        let err = String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned();
        (st.code().unwrap_or(-1), out, err)
    }
}

/// Text shown on the alternate screen between the header and the "press any key" footer.
pub fn shown_secret(screen: &str) -> String {
    let start = screen
        .rfind("\x1b[?1049h\x1b[H\x1b[2J")
        .expect("alternate screen")
        + "\x1b[?1049h\x1b[H\x1b[2J".len();
    let body = &screen[start..];
    let body = body.split("\r\n\r\n(press any key").next().unwrap();
    body.split_once("\r\n\r\n")
        .unwrap()
        .1
        .trim_end_matches(['\r', '\n'])
        .to_owned()
}

/// `init --own-passphrase` with PASS; returns the recovery key.
pub fn init(root: &Root) -> String {
    let mut s = Session::start(root, &["init", "--own-passphrase"]);
    s.expect("New passphrase");
    s.send(PASS);
    s.expect("Repeat it:");
    s.send(PASS);
    let screen = s.expect("(press any key to clear)");
    let rk = shown_secret(&screen);
    s.expect("Type the recovery key back");
    s.send(&rk);
    let (code, out, err) = s.finish();
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty());
    assert!(err.contains("keygent: vault created"));
    rk
}

/// Run a command that asks for the passphrase, then feeds `lines`.
pub fn run(root: &Root, args: &[&str], lines: &[&str]) -> (i32, String, String) {
    let mut s = Session::start(root, args);
    for l in lines {
        s.send(l);
    }
    s.finish()
}

pub fn add(root: &Root, handle: &str, value: &str) -> (i32, String, String) {
    run(root, &["add", handle], &[PASS, value])
}

pub fn verify_list(root: &Root) -> String {
    let (code, _, err) = run(root, &["verify"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    err
}

/// The canary must never appear in plaintext in any file under the root.
pub fn assert_no_plaintext(root: &Root, c: &str) {
    pub fn walk(p: &Path, c: &str) {
        for e in std::fs::read_dir(p).unwrap().flatten() {
            let path = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(&path, c);
            } else if ft.is_file() {
                let b = std::fs::read(&path).unwrap();
                assert!(
                    !b.windows(c.len()).any(|w| w == c.as_bytes()),
                    "canary in {}",
                    path.display()
                );
            }
        }
    }
    walk(&root.0, c);
}

pub fn unseal(root: &Root, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["unseal"];
    args.extend_from_slice(extra);
    run(root, &args, &[PASS])
}

pub fn broker_pid(root: &Root) -> i32 {
    let s = std::fs::read_to_string(root.0.join("run/broker.lock")).unwrap();
    s.split_whitespace().nth(1).unwrap().parse().unwrap()
}

pub fn wait_until(mut f: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

pub const WAITING: &str = "keygent: waiting for approval — ask the user to run 'keygent approve'";

/// An unsealed vault with `svc/key` = a canary, and a project dir (`.git`) to run in.
pub fn run_setup() -> (Root, String, PathBuf) {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "svc/key", &c).0, 0);
    assert_eq!(unseal(&root, &[]).0, 0);
    let proj = root.0.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    (root, c, proj)
}

pub fn run_in(root: &Root, proj: &Path, args: &[&str]) -> Session {
    let mut c = cmd(root, args);
    c.current_dir(proj);
    Session::start_cmd(c)
}

pub fn approve(root: &Root) {
    let (code, _, err) = run(root, &["approve"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("keygent: approved"), "{err}");
}

pub fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
