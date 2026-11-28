//! End-to-end CLI tests (SPEC §11): the real binary, isolated under `KEYGENT_TEST_ROOT` (test-profile feature),
//! driven through its console (stdin/stderr in test builds). Canaries only: `KEYGENT_CANARY_<random>`.
//! Run with `cargo test --features test-profile`.
#![cfg(feature = "test-profile")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::type_complexity,
    reason = "tests: a panic is the failure report"
)]

use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASS: &str = "orbit-canyon-velvet-anchor-mosaic-tundra";
const PASS2: &str = "cherisher-fanciness-hurray-natural-refuse-truce";

fn rand_u64() -> u64 {
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

fn canary() -> String {
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

struct Root(PathBuf);
impl Root {
    fn new() -> Root {
        Self::under(&std::env::temp_dir())
    }
    fn under(dir: &Path) -> Root {
        let p = dir.join(format!("kg-cli-{:016x}", rand_u64()));
        std::fs::create_dir_all(&p).unwrap();
        Root(p)
    }
    fn data(&self) -> PathBuf {
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

fn cmd(root: &Root, args: &[&str]) -> Command {
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
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    err: Arc<Mutex<Vec<u8>>>,
    out: Arc<Mutex<Vec<u8>>>,
    seen: usize,
}

impl Session {
    fn start(root: &Root, args: &[&str]) -> Session {
        Self::start_cmd(cmd(root, args))
    }
    fn start_cmd(mut c: Command) -> Session {
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
    fn expect(&mut self, pat: &str) -> String {
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
    fn send(&mut self, line: &str) {
        // the child may already have exited (an error before all answers were read)
        let s = self.stdin.as_mut().unwrap();
        let _ = s
            .write_all(line.as_bytes())
            .and_then(|()| s.write_all(b"\n"))
            .and_then(|()| s.flush());
    }
    fn finish(mut self) -> (i32, String, String) {
        drop(self.stdin.take());
        let st = self.child.wait().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let out = String::from_utf8_lossy(&self.out.lock().unwrap()).into_owned();
        let err = String::from_utf8_lossy(&self.err.lock().unwrap()).into_owned();
        (st.code().unwrap_or(-1), out, err)
    }
}

/// Text shown on the alternate screen between the header and the "press any key" footer.
fn shown_secret(screen: &str) -> String {
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
fn init(root: &Root) -> String {
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
fn run(root: &Root, args: &[&str], lines: &[&str]) -> (i32, String, String) {
    let mut s = Session::start(root, args);
    for l in lines {
        s.send(l);
    }
    s.finish()
}

fn add(root: &Root, handle: &str, value: &str) -> (i32, String, String) {
    run(root, &["add", handle], &[PASS, value])
}

fn verify_list(root: &Root) -> String {
    let (code, _, err) = run(root, &["verify"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    err
}

/// The canary must never appear in plaintext in any file under the root.
fn assert_no_plaintext(root: &Root, c: &str) {
    fn walk(p: &Path, c: &str) {
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

#[test]
fn init_add_reveal_and_no_plaintext_on_disk() {
    let root = Root::new();
    init(&root);
    let c = canary();
    let (code, out, err) = add(&root, "stripe/live", &c);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty() && !err.contains(&c));
    assert_no_plaintext(&root, &c);
    // permissions: owner-only dirs and files, pepper outside the data dir
    use std::os::unix::fs::PermissionsExt;
    for p in [root.data(), root.0.join("state")] {
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o700,
            "{}",
            p.display()
        );
    }
    for p in [
        root.data().join("vault.kgt"),
        root.0.join("state/device.key"),
    ] {
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600,
            "{}",
            p.display()
        );
    }
    assert!(!root.data().join("device.key").exists());
    // reveal shows the value on the (test) console only, never stdout
    let (code, out, err) = run(&root, &["reveal", "stripe/live"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty());
    assert_eq!(shown_secret(&err), c);
    assert!(
        err.contains("\x1b[?1049h") && err.contains("\x1b[?1049l"),
        "alternate screen used"
    );
}

#[test]
fn agent_facing_contract() {
    let root = Root::new();
    // no vault
    let (code, _, err) = run(&root, &["add", "x/y"], &[]);
    assert_eq!(
        (code, err.trim()),
        (1, "keygent: no vault yet — run 'keygent init'")
    );
    init(&root);
    // ls while sealed → 78 with the canonical line
    let (code, out, err) = run(&root, &["ls"], &[]);
    assert_eq!(
        (code, out.as_str(), err.trim()),
        (
            78,
            "",
            "keygent: vault sealed — ask the user to run 'keygent unseal'"
        )
    );
    // usage errors exit 64 before any prompt
    for args in [
        &["add"][..],
        &["add", "Bad Handle"],
        &["add", "a", "--bogus"],
        &["frobnicate"],
        &["rename", "a"],
    ] {
        let (code, _, err) = run(&root, args, &[]);
        assert_eq!(code, 64, "{args:?}: {err}");
        assert!(
            err.starts_with("keygent: ")
                && err.lines().count() == 1
                && err.trim().chars().count() <= 120,
            "{err}"
        );
    }
    // agent marker refuses auth commands (UX only)
    let mut c = cmd(&root, &["add", "x/y"]);
    c.env("CLAUDECODE", "1");
    let (code, _, err) = Session::start_cmd(c).finish();
    assert_eq!(
        (code, err.trim()),
        (
            1,
            "keygent: this needs your passphrase — run it in your own terminal"
        )
    );
}

#[test]
fn value_and_name_validation() {
    let root = Root::new();
    init(&root);
    let (code, _, err) = add(&root, "weak", "Passw0rd!2024");
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (
            1,
            "keygent: value too weak to redact safely — rotate it at the provider to a longer one"
        )
    );
    let (code, _, err) = add(&root, "short", "abc");
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (1, "keygent: value must be 12 bytes to 64 KiB")
    );
    let (code, _, err) = run(&root, &["add", "x", "--env", "LD_PRELOAD"], &[]);
    assert_eq!(
        (code, err.trim()),
        (1, "keygent: env name LD_PRELOAD is reserved — pick another")
    );
    let c = canary();
    assert_eq!(add(&root, "stripe/live", &c).0, 0);
    let (code, _, err) = add(&root, "stripe/live", &canary());
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (
            1,
            "keygent: stripe/live already exists — use 'keygent rotate' to change it"
        )
    );
    let (code, _, err) = add(&root, "stripe.live", &canary());
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (
            1,
            "keygent: name clashes with stripe/live — pick another handle"
        )
    );
    let (code, _, err) = run(
        &root,
        &["add", "z"],
        &["wrong one", "wrong two", "wrong three"],
    );
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (1, "keygent: wrong passphrase — nothing changed")
    );
}

#[test]
fn rotate_undo_rename_rm() {
    let root = Root::new();
    init(&root);
    let (c1, c2) = (canary(), canary());
    assert_eq!(add(&root, "gh/token", &c1).0, 0);
    let (code, _, err) = run(&root, &["rotate", "gh/token"], &[PASS, &c2]);
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = run(&root, &["reveal", "gh/token"], &[PASS]);
    assert_eq!(shown_secret(&err), c2);
    assert!(
        !root.data().join("vault.kgt.prev").exists(),
        "rotate drops .prev"
    );
    let (code, _, err) = run(&root, &["rotate", "gh/token", "--undo"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = run(&root, &["reveal", "gh/token"], &[PASS]);
    assert_eq!(shown_secret(&err), c1);
    let (code, _, err) = run(&root, &["rename", "gh/token", "github/token"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = run(&root, &["reveal", "github/token"], &[PASS]);
    assert_eq!(shown_secret(&err), c1);
    let (code, _, _) = run(&root, &["rm", "github/token"], &[PASS, "n"]);
    assert_eq!(code, 1);
    let (code, _, err) = run(&root, &["rm", "github/token"], &[PASS, "y"]);
    assert_eq!(code, 0, "{err}");
    assert!(!verify_list(&root).contains("github/token"));
    assert_no_plaintext(&root, &c1);
    assert_no_plaintext(&root, &c2);
}

#[test]
fn multiline_and_from_file() {
    let root = Root::new();
    init(&root);
    let pem = format!(
        "-----BEGIN KEY-----\n{}\n{}\n-----END KEY-----",
        canary(),
        canary()
    );
    let mut lines = vec![PASS];
    lines.extend(pem.lines());
    lines.push(".");
    let (code, _, err) = run(&root, &["add", "gcp/sa", "--multiline"], &lines);
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = run(&root, &["reveal", "gcp/sa"], &[PASS]);
    assert_eq!(shown_secret(&err).replace("\r\n", "\n"), pem);
    // --from-file with --delete
    let f = root.0.join("sa.json");
    let c = canary();
    std::fs::write(&f, format!("{{\"key\":\"{c}\"}}")).unwrap();
    let (code, _, err) = run(
        &root,
        &[
            "add",
            "gcp/json",
            "--from-file",
            f.to_str().unwrap(),
            "--delete",
        ],
        &[PASS],
    );
    assert_eq!(code, 0, "{err}");
    assert!(!f.exists());
    assert!(
        !err.contains(f.to_str().unwrap()),
        "file path never printed"
    );
    // symlinked input refused
    let real = root.0.join("real.txt");
    std::fs::write(&real, canary()).unwrap();
    let link = root.0.join("link.txt");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (code, _, err) = run(
        &root,
        &["add", "x/link", "--from-file", link.to_str().unwrap()],
        &[PASS],
    );
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (1, "keygent: not a regular file owned by you")
    );
}

#[test]
fn passwd_recover_rekey() {
    let root = Root::new();
    let rk = init(&root);
    let c = canary();
    assert_eq!(add(&root, "a/b", &c).0, 0);
    let (code, _, err) = run(
        &root,
        &["passwd", "--own-passphrase"],
        &[PASS, PASS2, PASS2],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(run(&root, &["verify"], &[PASS]).0, 1);
    // recover with the recovery key: new passphrase + new recovery key
    let mut s = Session::start(&root, &["recover", "--own-passphrase"]);
    s.expect("Recovery key:");
    s.send(&rk.to_lowercase().replace('-', " "));
    s.expect("New passphrase");
    s.send(PASS);
    s.expect("Repeat it:");
    s.send(PASS);
    let rk2 = shown_secret(&s.expect("(press any key to clear)"));
    s.expect("Type the recovery key back");
    s.send(&rk2);
    let (code, _, err) = s.finish();
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = run(&root, &["reveal", "a/b"], &[PASS]);
    assert_eq!(shown_secret(&err), c);
    // the old recovery key stopped working
    let (code, _, err) = run(&root, &["recover", "--own-passphrase"], &[&rk]);
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (1, "keygent: wrong recovery key — nothing changed")
    );
    // a typo is caught by the checksum
    let (code, _, _) = run(
        &root,
        &["recover"],
        &["0000000-0000000-0000000-0000000-000000-000000-000000-000000-00"],
    );
    assert_eq!(code, 1);
}

#[test]
fn backup_restore_and_new_machine() {
    let root = Root::new();
    let rk = init(&root);
    let c = canary();
    assert_eq!(add(&root, "svc/key", &c).0, 0);
    let bk = root.0.join("vault.backup");
    let (code, _, err) = run(&root, &["backup", bk.to_str().unwrap()], &[]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        run(&root, &["backup", bk.to_str().unwrap()], &[]).0,
        64,
        "never overwrites"
    );
    // change the live vault, then restore the backup: the tripwire flags the older generation
    assert_eq!(add(&root, "svc/other", &canary()).0, 0);
    let (code, _, err) = run(&root, &["restore", bk.to_str().unwrap()], &[PASS, "n"]);
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (
            1,
            "keygent: vault is older than expected (rolled back?) — nothing changed"
        )
    );
    let (code, _, err) = run(&root, &["restore", bk.to_str().unwrap()], &[PASS, "y"]);
    assert_eq!(code, 0, "{err}");
    assert!(!verify_list(&root).contains("svc/other"));
    // a new machine: fresh root, no device key — recovery key + new passphrase
    let other = Root::new();
    let mut s = Session::start(
        &other,
        &[
            "restore",
            bk.to_str().unwrap(),
            "--new-machine",
            "--own-passphrase",
        ],
    );
    s.expect("Recovery key:");
    s.send(&rk);
    s.expect("New passphrase");
    s.send(PASS2);
    s.expect("Repeat it:");
    s.send(PASS2);
    let (code, _, err) = s.finish();
    assert_eq!(code, 0, "{err}");
    let (_, _, err) = run(&other, &["reveal", "svc/key"], &[PASS2]);
    assert_eq!(shown_secret(&err), c);
    // the backup does not open with the passphrase on a machine without this device key
    let third = Root::new();
    let (code, _, err) = run(&third, &["restore", bk.to_str().unwrap()], &[PASS]);
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (
            1,
            "keygent: this device's key is missing — run 'keygent recover' with your recovery key"
        )
    );
}

#[test]
fn import_env_file() {
    let root = Root::new();
    init(&root);
    let (c1, c2) = (canary(), canary());
    let env = root.0.join(".env");
    std::fs::write(&env, format!("# test\nSTRIPE_API_KEY={c1}\nexport GH_TOKEN=\"{c2}\"\nWEAK=password1\nLD_PRELOAD={}\n", canary()))
        .unwrap();
    let (code, out, err) = run(
        &root,
        &["import", env.to_str().unwrap(), "--delete"],
        &[PASS, "y"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty() && !err.contains(&c1) && !err.contains(&c2));
    assert!(err.contains("skip  WEAK") && err.contains("skip  LD_PRELOAD"));
    assert!(!env.exists());
    let (_, _, e) = run(&root, &["reveal", "stripe-api-key"], &[PASS]);
    assert_eq!(shown_secret(&e), c1);
    let (_, _, e) = run(&root, &["reveal", "gh-token"], &[PASS]);
    assert_eq!(shown_secret(&e), c2);
    // a parse error names only the line
    std::fs::write(&env, format!("A={}\nB=\"{c1}", canary())).unwrap();
    let (code, _, err) = run(&root, &["import", env.to_str().unwrap()], &[]);
    assert_eq!(code, 1);
    assert!(err.contains("line 2") && !err.contains(&c1));
}

#[test]
fn edit_policy_and_settings() {
    let root = Root::new();
    init(&root);
    assert_eq!(add(&root, "s/k", &canary()).0, 0);
    let (code, _, err) = run(
        &root,
        &["edit", "s/k", "--mode", "deny", "--env", "SVC_KEY"],
        &[PASS, "y"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("mode:        approve → deny") && err.contains("env:         S_K → SVC_KEY")
    );
    let (code, _, err) = run(&root, &["edit", "s/k", "--argv", "allow"], &[PASS, "y"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("⚠ argv allow"));
    let (code, _, err) = run(
        &root,
        &[
            "edit",
            "--settings",
            "--run-max-minutes",
            "240",
            "--remember",
            "off",
        ],
        &[PASS, "y"],
    );
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        run(
            &root,
            &["edit", "--settings", "--run-max-minutes", "241"],
            &[]
        )
        .0,
        64
    );
    assert_eq!(
        run(&root, &["edit", "--settings", "--ttl-max", "90000"], &[]).0,
        64
    );
}

#[test]
fn verify_detects_damage_and_offers_prev() {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "a/one", &c).0, 0);
    assert_eq!(add(&root, "a/two", &canary()).0, 0); // .prev = vault with a/one only
    let p = root.data().join("vault.kgt");
    let mut b = std::fs::read(&p).unwrap();
    let n = b.len();
    b[n - 1] ^= 1; // last entry (a/two)
    std::fs::write(&p, b).unwrap();
    let (code, _, err) = run(&root, &["verify"], &[PASS, "y"]);
    assert!(
        err.contains("ok       a/one") && err.contains("DAMAGED  a/two"),
        "{err}"
    );
    assert!(err.contains("restored vault.kgt.prev"), "{err}");
    assert_eq!(code, 0);
    let (code, _, err) = run(&root, &["reveal", "a/one"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(shown_secret(&err), c);
}

#[test]
fn version_and_status() {
    let root = Root::new();
    let (code, out, _) = run(&root, &["version"], &[]);
    assert_eq!(code, 0);
    assert!(out.starts_with("keygent 0.0.0 ("));
    let (_, out, _) = run(&root, &["status"], &[]);
    assert_eq!(out.trim(), "keygent: no vault — run 'keygent init'");
}

/// Disk full (SPEC §5.2): the vault stays intact and the user gets the canonical line. Runs only when
/// `KEYGENT_TEST_SMALLFS` names a small dedicated filesystem (the Linux container task mounts a 2 MiB tmpfs).
#[test]
fn disk_full_leaves_vault_intact() {
    let Some(fs) = std::env::var_os("KEYGENT_TEST_SMALLFS") else {
        eprintln!("disk_full_leaves_vault_intact: skipped (set KEYGENT_TEST_SMALLFS)");
        return;
    };
    let root = Root::under(Path::new(&fs));
    init(&root);
    assert_eq!(add(&root, "a/one", &canary()).0, 0);
    let value_file = root.0.join("big.txt");
    let big: String = (0..2000).map(|_| canary()).collect::<Vec<_>>().join("")[..60_000].to_owned();
    std::fs::write(&value_file, &big).unwrap();
    let before = std::fs::read(root.data().join("vault.kgt")).unwrap();
    // fill the filesystem completely
    let mut filler = std::fs::File::create(root.0.join("filler")).unwrap();
    let chunk = vec![0u8; 64 * 1024];
    loop {
        if filler.write_all(&chunk).is_err() {
            break;
        }
    }
    let mut small = vec![0u8; 4096];
    while filler.write_all(&small[..1]).is_ok() {}
    small.clear();
    let (code, _, err) = run(
        &root,
        &["add", "a/big", "--from-file", value_file.to_str().unwrap()],
        &[PASS],
    );
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (1, "keygent: disk full — vault unchanged")
    );
    assert_eq!(
        std::fs::read(root.data().join("vault.kgt")).unwrap(),
        before
    );
    let leftovers: Vec<_> = std::fs::read_dir(root.data())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind");
    drop(filler);
    std::fs::remove_file(root.0.join("filler")).unwrap();
    assert_eq!(run(&root, &["verify"], &[PASS]).0, 0);
}

// ---------------------------------------------------------------- broker (Phase 2)

fn unseal(root: &Root, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["unseal"];
    args.extend_from_slice(extra);
    run(root, &args, &[PASS])
}

fn broker_pid(root: &Root) -> i32 {
    let s = std::fs::read_to_string(root.0.join("run/broker.lock")).unwrap();
    s.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn wait_until(mut f: impl FnMut() -> bool) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn unseal_status_ls_seal() {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "a/b", &c).0, 0);
    let (code, out, err) = unseal(&root, &[]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.is_empty() && err.contains("keygent: unsealed for 8h00m"),
        "{err}"
    );
    // a second unseal is a no-op
    let (code, _, err) = run(&root, &["unseal"], &[]);
    assert_eq!((code, err.trim()), (0, "keygent: already unsealed"));
    let (code, out, _) = run(&root, &["status"], &[]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("keygent: unsealed — 7h59m left")
            || out.starts_with("keygent: unsealed — 8h00m left"),
        "{out}"
    );
    assert!(
        out.contains("1 secret(s)") && out.contains("hardening on"),
        "{out}"
    );
    let (code, out, err) = run(&root, &["ls"], &[]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "a/b  $A_B  approve\n");
    // a CLI write while unsealed is picked up by the broker (ADR 0012 reload)
    assert_eq!(add(&root, "c/d", &canary()).0, 0);
    let (_, out, _) = run(&root, &["ls"], &[]);
    assert_eq!(out, "a/b  $A_B  approve\nc/d  $C_D  approve\n");
    // runtime files are owner-only; the broker log never contains the value
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(root.0.join("run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(root.0.join("run/broker.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let pid = broker_pid(&root);
    let (code, _, err) = run(&root, &["seal"], &[]);
    assert_eq!((code, err.trim()), (0, "keygent: sealed"));
    assert!(wait_until(|| std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)));
    let (code, _, err) = run(&root, &["ls"], &[]);
    assert_eq!(
        (code, err.trim()),
        (
            78,
            "keygent: vault sealed — ask the user to run 'keygent unseal'"
        )
    );
    let (_, out, _) = run(&root, &["status"], &[]);
    assert_eq!(out.trim(), "keygent: vault sealed");
    assert_no_plaintext(&root, &c);
}

#[test]
fn broker_seals_on_ttl_signal_and_tamper() {
    let root = Root::new();
    init(&root);
    assert_eq!(add(&root, "a/b", &canary()).0, 0);
    // TTL
    assert_eq!(unseal(&root, &["--ttl", "2s"]).0, 0);
    assert!(wait_until(|| run(&root, &["ls"], &[]).0 == 78), "TTL seal");
    // SIGTERM
    assert_eq!(unseal(&root, &[]).0, 0);
    let pid = broker_pid(&root);
    assert!(
        std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        wait_until(|| run(&root, &["ls"], &[]).0 == 78),
        "SIGTERM seal"
    );
    // tampered vault (MAC fails on reload) → the broker seals instead of serving stale or forged data
    assert_eq!(unseal(&root, &[]).0, 0);
    let p = root.data().join("vault.kgt");
    let mut b = std::fs::read(&p).unwrap();
    b[22] ^= 1; // generation: forces a reload, and breaks the header MAC
    std::fs::write(&p, b).unwrap();
    let (code, _, _) = run(&root, &["ls"], &[]);
    assert_ne!(code, 0);
    assert!(
        wait_until(|| run(&root, &["ls"], &[]).0 == 78),
        "tamper seal"
    );
}

#[test]
fn fake_broker_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let root = Root::new();
    init(&root);
    let run_dir = root.0.join("run");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // an agent squats the endpoint with its own listener (no held lock, wrong pid, wrong binary)
    let l = std::os::unix::net::UnixListener::bind(run_dir.join("broker.sock")).unwrap();
    let t = std::thread::spawn(move || {
        for s in l.incoming().take(2).flatten() {
            let mut s = s;
            let _ = s.write_all(b"\x00\x00\x00\x02\x01\x02");
        }
    });
    let (code, out, err) = run(&root, &["ls"], &[]);
    assert_eq!(
        (code, out.as_str(), err.trim()),
        (
            79,
            "",
            "keygent: broker could not be verified — run 'keygent doctor'"
        )
    );
    // even with a forged broker.lock naming this process and holding the lock
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(run_dir.join("broker.lock"))
        .unwrap();
    std::fs::set_permissions(
        run_dir.join("broker.lock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    (&lock)
        .write_all(
            format!(
                "v1 {} 1 {}\n",
                std::process::id(),
                std::env::current_exe().unwrap().display()
            )
            .as_bytes(),
        )
        .unwrap();
    lock.lock().unwrap();
    let (code, _, err) = run(&root, &["ls"], &[]);
    assert_eq!(
        (code, err.trim()),
        (
            79,
            "keygent: broker could not be verified — run 'keygent doctor'"
        )
    );
    // unseal refuses to hand a DEK to a squatter
    let (code, _, _) = run(&root, &["unseal"], &[PASS]);
    assert_eq!(code, 79);
    drop(lock);
    let _ = std::os::unix::net::UnixStream::connect(run_dir.join("broker.sock"));
    let _ = t.join();
}

#[test]
fn stale_socket_after_crash_is_recovered() {
    let root = Root::new();
    init(&root);
    assert_eq!(unseal(&root, &[]).0, 0);
    let pid = broker_pid(&root);
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert!(wait_until(|| std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)));
    assert!(
        root.0.join("run/broker.sock").exists(),
        "socket left behind by the crash"
    );
    // the lock is free and nothing answers, so the endpoint reads as sealed, and a new unseal rebinds it
    assert_eq!(
        run(&root, &["ls"], &[]).0,
        78,
        "a dead endpoint reads as sealed"
    );
    let (code, _, err) = unseal(&root, &[]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(run(&root, &["ls"], &[]).0, 0);
}

#[test]
fn passwd_seals_the_broker_first() {
    let root = Root::new();
    init(&root);
    assert_eq!(unseal(&root, &[]).0, 0);
    let (code, _, err) = run(
        &root,
        &["passwd", "--own-passphrase"],
        &[PASS, PASS2, PASS2],
    );
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("keygent: sealed the running broker first"),
        "{err}"
    );
    assert_eq!(run(&root, &["ls"], &[]).0, 78);
}

#[test]
fn broker_redacts_values_old_values_and_detectors() {
    let root = Root::new();
    init(&root);
    let (c1, c2) = (canary(), canary());
    assert_eq!(add(&root, "svc/key", &c1).0, 0);
    assert_eq!(unseal(&root, &[]).0, 0);
    let redact = |input: &str| {
        let mut c = cmd(&root, &["__redact"]);
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let o = child.wait_with_output().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    };
    let b64 = {
        let mut s = String::new();
        let t = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for ch in c1.as_bytes().chunks(3) {
            let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for k in 0..=ch.len() {
                s.push(t[((n >> (18 - 6 * k)) & 63) as usize] as char);
            }
        }
        s
    };
    let out = redact(&format!("raw {c1} b64 {b64} aws AKIAIOSFODNN7EXAMPLE\n"));
    assert!(
        !out.contains(&c1) && !out.contains(&b64[..20]) && !out.contains("AKIAIOSFODNN7EXAMPLE"),
        "{out}"
    );
    assert!(
        out.contains("‹keygent:svc/key›") && out.contains("‹keygent:unknown›"),
        "{out}"
    );
    // after a rotate (a CLI write while unsealed), the broker redacts the new value and still the old one
    assert_eq!(run(&root, &["rotate", "svc/key"], &[PASS, &c2]).0, 0);
    let out = redact(&format!("{c1} {c2}"));
    assert_eq!(out, "‹keygent:svc/key› ‹keygent:svc/key›");
}

// ---------------------------------------------------------------- grants, approvals and run (Phase 2 M3)

const WAITING: &str = "keygent: waiting for approval — ask the user to run 'keygent approve'";

/// An unsealed vault with `svc/key` = a canary, and a project dir (`.git`) to run in.
fn run_setup() -> (Root, String, PathBuf) {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "svc/key", &c).0, 0);
    assert_eq!(unseal(&root, &[]).0, 0);
    let proj = root.0.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    (root, c, proj)
}

fn run_in(root: &Root, proj: &Path, args: &[&str]) -> Session {
    let mut c = cmd(root, args);
    c.current_dir(proj);
    Session::start_cmd(c)
}

fn approve(root: &Root) {
    let (code, _, err) = run(root, &["approve"], &[PASS]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("keygent: approved"), "{err}");
}

fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn run_with_approval_streams_redacted_output() {
    let (root, c, proj) = run_setup();
    let mut s = run_in(
        &root,
        &proj,
        &[
            "run",
            "--",
            "X={{keygent:svc/key}} sh -c 'printf \"%s\\n\" \"$X\"; echo to-stderr >&2; exit 3'",
        ],
    );
    s.expect(WAITING);
    // the request as the human sees it: command, cwd, secret → env, programs, unbound warning
    let (code, out, _) = run(&root, &["pending"], &[]);
    assert_eq!(code, 0);
    for want in [
        "request ",
        "X={{keygent:svc/key}} sh -c",
        "svc/key → $KEYGENT_SVC_KEY",
        "program:  /",
        "⚠ unbound",
    ] {
        assert!(out.contains(want), "missing {want}: {out}");
    }
    assert!(!out.contains(&c));
    approve(&root);
    let (code, out, err) = s.finish();
    assert_eq!(code, 3, "{err}");
    assert_eq!(out, "‹keygent:svc/key›\n");
    assert!(err.contains("to-stderr"), "{err}");
    assert!(!out.contains(&c) && !err.contains(&c));
    // the grant was single-use and nothing is pending any more
    let (_, out, _) = run(&root, &["pending"], &[]);
    assert_eq!(out, "no pending requests\n");
    assert_no_plaintext(&root, &c);
}

#[test]
fn deny_and_policy_refusals() {
    let (root, _c, proj) = run_setup();
    let mut s = run_in(&root, &proj, &["run", "--", "X={{keygent:svc/key}} true"]);
    s.expect(WAITING);
    let (code, _, err) = run(&root, &["deny"], &[]);
    assert_eq!((code, err.trim()), (0, "keygent: denied"));
    let (code, _, err) = s.finish();
    assert_eq!(
        (code, err.lines().last().unwrap()),
        (75, "keygent: approval denied or timed out for svc/key")
    );
    // refusals happen before anything is queued
    let refuse = |c: &str, cwd: &Path| {
        let mut x = cmd(&root, &["run", "--", c]);
        x.current_dir(cwd);
        let o = x.output().unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8(o.stderr).unwrap(),
        )
    };
    let (code, err) = refuse("tool --key {{keygent:svc/key}}", &proj);
    assert_eq!(code, 77);
    assert!(
        err.starts_with("keygent: secret would be visible in the process list"),
        "{err}"
    );
    let (code, err) = refuse("X='{{keygent:svc/key}}' tool", &proj);
    assert_eq!(
        (code, err.trim()),
        (
            77,
            "keygent: placeholder inside single quotes won't expand — use double quotes"
        )
    );
    let (code, err) = refuse("X={{keygent:no/such}} tool", &proj);
    assert_eq!(code, 77, "{err}");
    let (code, err) = refuse("echo hi", Path::new("/"));
    assert_eq!(
        (code, err.trim()),
        (
            77,
            "keygent: can't approve runs from this folder — run inside a project"
        )
    );
    let (code, err) = refuse("echo 'unterminated", &proj);
    assert_eq!(code, 64, "{err}");
    // approve with nothing pending
    let (code, _, err) = run(&root, &["approve"], &[]);
    assert_eq!((code, err.trim()), (1, "keygent: no pending requests"));
    // a command without placeholders runs without approval
    let mut x = cmd(&root, &["run", "--", "echo hi; exit 4"]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(
        (o.status.code(), o.stdout.as_slice()),
        (Some(4), b"hi\n".as_slice())
    );
}

#[test]
fn bound_script_runs_the_approved_bytes() {
    let (root, c, proj) = run_setup();
    std::fs::write(proj.join("x.sh"), "printf '%s|' \"$X\"\n").unwrap();
    let mut s = run_in(
        &root,
        &proj,
        &["run", "--", "X={{keygent:svc/key}} sh ./x.sh"],
    );
    s.expect(WAITING);
    let (_, out, _) = run(&root, &["pending"], &[]);
    assert!(
        out.contains("--- ") && out.contains("printf '%s|'"),
        "script shown in full: {out}"
    );
    // swapping the script after approval-time reading has no effect
    std::fs::write(proj.join("x.sh"), "echo SWAPPED\n").unwrap();
    approve(&root);
    let (code, out, err) = s.finish();
    assert_eq!((code, out.as_str()), (0, "‹keygent:svc/key›|"), "{err}");
    assert!(!out.contains(&c));
}

#[test]
fn changed_program_after_approval_fails_closed() {
    let (root, _c, proj) = run_setup();
    std::fs::create_dir_all(proj.join("bin")).unwrap();
    let tool = proj.join("bin/tool");
    std::fs::copy("/bin/echo", &tool).unwrap();
    let mut s = run_in(
        &root,
        &proj,
        &["run", "--", "X={{keygent:svc/key}} ./bin/tool hi"],
    );
    s.expect(WAITING);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&tool)
        .unwrap();
    f.write_all(b"\0").unwrap();
    drop(f);
    approve(&root);
    let (code, out, err) = s.finish();
    assert_eq!(code, 77, "{err}");
    assert!(out.is_empty());
    assert!(err.ends_with("keygent: a program or script changed after approval — re-run to request approval again\n"), "{err}");
}

#[test]
fn run_limits_and_containment() {
    let (root, _c, proj) = run_setup();
    // runtime cap: exit 74 with the canonical line; the backgrounded child dies with the session
    let mut x = cmd(
        &root,
        &[
            "run",
            "--max-runtime",
            "2s",
            "--",
            "sleep 30 & echo $!; sleep 30",
        ],
    );
    x.current_dir(&proj);
    let t = Instant::now();
    let o = x.output().unwrap();
    assert!(t.elapsed() < Duration::from_secs(10));
    let err = String::from_utf8(o.stderr).unwrap();
    assert_eq!(o.status.code(), Some(74), "{err}");
    assert_eq!(
        err.trim(),
        "keygent: run stopped at its limit (1 min / 10 MiB) — use --max-runtime or run_in_background"
    );
    let bg = String::from_utf8(o.stdout).unwrap();
    assert!(
        wait_until(|| !alive(bg.trim())),
        "background child {bg} survived"
    );
    // output cap
    let mut x = cmd(&root, &["run", "--", "head -c 11000000 /dev/zero"]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(o.status.code(), Some(74));
    assert!(o.stdout.len() <= 10 * 1024 * 1024);
    // a killed client kills its run
    let mut s = run_in(&root, &proj, &["run", "--", "echo $$; sleep 30"]);
    assert!(
        wait_until(|| s.out.lock().unwrap().ends_with(b"\n")),
        "run never printed its pid"
    );
    let pid = String::from_utf8(s.out.lock().unwrap().clone())
        .unwrap()
        .trim()
        .to_owned();
    assert!(alive(&pid));
    s.child.kill().unwrap();
    let _ = s.finish();
    assert!(wait_until(|| !alive(&pid)), "run survived its client");
    // an interrupt is forwarded: sh dies of SIGINT → 130
    let s = run_in(&root, &proj, &["run", "--", "echo ready; sleep 30"]);
    assert!(
        wait_until(|| s.out.lock().unwrap().ends_with(b"ready\n")),
        "run never got ready"
    );
    Command::new("kill")
        .args(["-INT", &s.child.id().to_string()])
        .status()
        .unwrap();
    let (code, _, _) = s.finish();
    assert_eq!(code, 130);
}

// ---------------------------------------------------------------- audit chain (Phase 2 M4)

#[test]
fn audit_chain_records_verifies_and_fails_closed() {
    let (root, c, proj) = run_setup();
    let mut x = cmd(&root, &["run", "--", "echo hi"]);
    x.current_dir(&proj);
    assert!(x.output().unwrap().status.success());
    let (code, out, _) = run(&root, &["audit"], &[]);
    assert_eq!(code, 0);
    for ev in [
        "\"event\":\"add\"",
        "\"event\":\"unseal\"",
        "\"event\":\"grant\"",
        "\"decision\":\"start\"",
        "\"exit\":0",
    ] {
        assert!(out.contains(ev), "missing {ev}: {out}");
    }
    assert!(!out.contains(&c));
    let (code, _, err) = run(&root, &["audit", "--verify"], &[]);
    assert_eq!(code, 0, "{err}");
    assert!(err.starts_with("keygent: audit log intact ("), "{err}");
    // an edited record is detected
    let log = root.0.join("state/audit.jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::write(
        &log,
        text.replacen("\"event\":\"add\"", "\"event\":\"rm\"", 1),
    )
    .unwrap();
    let (code, _, err) = run(&root, &["audit", "--verify"], &[]);
    assert_eq!(
        (code, err.trim()),
        (
            79,
            "keygent: audit log tampered at record 1 — run 'keygent doctor'"
        )
    );
    // an unwritable log refuses runs and value changes (fail closed)
    std::fs::remove_file(&log).unwrap();
    std::fs::create_dir(&log).unwrap();
    let mut x = cmd(&root, &["run", "--", "echo hi"]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(o.status.code(), Some(79));
    assert_eq!(
        String::from_utf8(o.stderr).unwrap().trim(),
        "keygent: audit log unwritable — run 'keygent doctor'"
    );
    assert!(o.stdout.is_empty());
    let (code, _, err) = add(&root, "new/one", &canary());
    assert_eq!(code, 79, "{err}");
    let (_, out, _) = run(&root, &["ls"], &[]);
    assert!(!out.contains("new/one"));
}

// ---------------------------------------------------------------- allow rules (Phase 2 M4)

#[test]
fn allow_rules_run_pinned_tools_silently() {
    let (root, c, proj) = run_setup();
    let tool = proj.join("tool");
    std::fs::write(
        &tool,
        "#!/bin/sh\nprintf '%s|%s|%s\\n' \"$SVC_KEY\" \"$*\" \"$HOME\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    // shapes that can never be rules
    let mut x = cmd(&root, &["rule", "add", "svc/key", "--", "/bin/sh", "*"]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(o.status.code(), Some(64));
    let mut x = cmd(&root, &["rule", "add", "svc/key", "--", "./tool", "**"]);
    x.current_dir(&proj);
    assert_eq!(
        x.output().unwrap().status.code(),
        Some(64),
        "** needs flags"
    );
    // add a rule (passphrase), then switch the handle to allow mode
    let mut x = cmd(
        &root,
        &[
            "rule", "add", "svc/key", "--home", "scratch", "--", "./tool", "list", "*", "**",
            "--limit=",
        ],
    );
    x.current_dir(&proj);
    let mut s = Session::start_cmd(x);
    s.send(PASS);
    let (code, _, err) = s.finish();
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("rules apply only in 'allow'"), "{err}");
    let (code, _, err) = run(&root, &["edit", "svc/key", "--mode", "allow"], &[PASS, "y"]);
    assert_eq!(code, 0, "{err}");
    let go = |c: &str| {
        let mut x = cmd(&root, &["run", "--", c]);
        x.current_dir(&proj);
        let o = x.output().unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8(o.stdout).unwrap(),
            String::from_utf8(o.stderr).unwrap(),
        )
    };
    // a matching command runs at once, no approval, value injected under the handle's env name, redacted output,
    // scratch HOME
    let (code, out, err) = go("./tool list acme --limit 3");
    assert_eq!(code, 0, "{err}");
    assert!(err.is_empty(), "silent: {err}");
    assert!(
        out.starts_with("‹keygent:svc/key›|list acme --limit 3|"),
        "{out}"
    );
    assert!(
        out.contains("/h-") && out.trim_end().ends_with("/home"),
        "scratch home: {out}"
    );
    assert!(!out.contains(&c));
    // non-matching shapes get no secret (no rule → plain run without injection)
    let (code, out, _) = go("./tool list acme --other 1");
    assert_eq!(
        (code, out.starts_with("|list acme --other 1|")),
        (0, true),
        "{out}"
    );
    let (_, out, _) = go("./tool list -x");
    assert!(out.starts_with("|list -x|"), "{out}");
    // a changed binary falls back to approval with a re-pin warning
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&tool)
        .unwrap();
    f.write_all(b"# changed\n").unwrap();
    drop(f);
    let mut s = run_in(&root, &proj, &["run", "--", "./tool list acme"]);
    s.expect(WAITING);
    let (_, out, _) = run(&root, &["pending"], &[]);
    assert!(
        out.contains("⚠ re-pin:") && out.contains("allow rule matched"),
        "{out}"
    );
    assert!(!out.contains("⚠ unbound"), "a rule run is bound: {out}");
    approve(&root);
    let (code, out, err) = s.finish();
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("‹keygent:svc/key›|list acme|"), "{out}");
    // the audit trail shows the silent run
    let (_, out, _) = run(&root, &["audit"], &[]);
    assert!(out.contains("\"decision\":\"auto\""), "{out}");
    let (code, _, err) = run(&root, &["audit", "--verify"], &[]);
    assert_eq!(code, 0, "{err}");
}

// ---------------------------------------------------------------- manifest trust (Phase 2 M4)

#[test]
fn manifest_needs_trust_and_any_change_untrusts_it() {
    let (root, c, proj) = run_setup();
    let mf = proj.join(".keygent.toml");
    std::fs::write(
        &mf,
        "version = 1\n[secrets]\n\"svc/key\" = { env = \"SVC_TOKEN\" }\n",
    )
    .unwrap();
    let use_it = "X=\"$SVC_TOKEN\" sh -c 'printf \"%s\\n\" \"$X\"'";
    let go = |c: &str| {
        let mut x = cmd(&root, &["run", "--", c]);
        x.current_dir(&proj);
        let o = x.output().unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8(o.stderr).unwrap(),
        )
    };
    let not_trusted = "keygent: .keygent.toml changed — ask the user to run 'keygent trust'";
    assert_eq!(go(use_it), (76, format!("{not_trusted}\n")));
    // trust shows the whole file and the bindings, then needs the passphrase
    let mut x = cmd(&root, &["trust"]);
    x.current_dir(&proj);
    let mut s = Session::start_cmd(x);
    s.send(PASS);
    let (code, _, err) = s.finish();
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("  | \"svc/key\" = { env = \"SVC_TOKEN\" }"),
        "{err}"
    );
    assert!(
        err.contains("svc/key → $SVC_TOKEN") && err.contains("keygent: trusted "),
        "{err}"
    );
    // now a reference is an approval-required binding; the value is injected under the manifest's name
    let mut s = run_in(&root, &proj, &["run", "--", use_it]);
    s.expect(WAITING);
    let (_, out, _) = run(&root, &["pending"], &[]);
    assert!(
        out.contains("svc/key → $SVC_TOKEN") && out.contains("manifest: "),
        "{out}"
    );
    approve(&root);
    let (code, out, err) = s.finish();
    assert_eq!((code, out.as_str()), (0, "‹keygent:svc/key›\n"), "{err}");
    assert!(!out.contains(&c));
    // the argv rule applies to $NAME too
    let (code, err) = go("printf %s \"$SVC_TOKEN\"");
    assert_eq!(code, 77, "{err}");
    // unrelated variables need nothing
    let mut x = cmd(&root, &["run", "--", "echo \"$TERM\""]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(
        (o.status.code(), o.stdout.as_slice()),
        (Some(0), b"dumb\n".as_slice())
    );
    // any change un-trusts it
    let mut f = std::fs::OpenOptions::new().append(true).open(&mf).unwrap();
    f.write_all(b"# edited\n").unwrap();
    drop(f);
    assert_eq!(go(use_it), (76, format!("{not_trusted}\n")));
    // untrust is agent-safe (no passphrase) and drops the trust of the current content
    let mut x = cmd(&root, &["trust"]);
    x.current_dir(&proj);
    let mut s = Session::start_cmd(x);
    s.send(PASS);
    assert_eq!(s.finish().0, 0);
    let mut x = cmd(&root, &["untrust"]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(go(use_it), (76, format!("{not_trusted}\n")));
    // invalid manifests can't be trusted
    std::fs::write(
        &mf,
        "version = 1\n[secrets]\n\"svc/key\" = { env = \"PATH\" }\n",
    )
    .unwrap();
    let mut x = cmd(&root, &["trust"]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        String::from_utf8(o.stderr)
            .unwrap()
            .contains("line 3 is not valid")
    );
    let (code, _, err) = run(&root, &["audit", "--verify"], &[]);
    assert_eq!(code, 0, "{err}");
}

// ---------------------------------------------------------------- capture (Phase 2 M4)

#[test]
fn capture_stores_stdout_as_a_new_handle_without_showing_it() {
    let (root, _c, proj) = run_setup();
    let make = "v=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \\n'); echo \"  $v\"; echo \"token=$v\" >&2";
    // every capture writes a secret, so every capture needs the human's approval (review fix)
    let approved = |args: &[&str]| {
        let mut s = run_in(&root, &proj, args);
        s.expect(WAITING);
        approve(&root);
        s.finish()
    };
    let (code, out, err) = approved(&["capture", "new/tok", "--", make]);
    assert_eq!(code, 0, "{err}");
    assert!(out.is_empty(), "stdout is never returned: {out}");
    assert!(
        err.contains("token=‹keygent:new/tok›"),
        "stderr redacted with the new value: {err}"
    );
    assert!(
        err.ends_with("keygent: stored new/tok (env KEYGENT_NEW_TOK, mode approve)\n"),
        "{err}"
    );
    let (_, out, _) = run(&root, &["ls"], &[]);
    assert!(out.contains("new/tok  $KEYGENT_NEW_TOK  approve"), "{out}");
    // the stored value is usable (and redacted) like any other
    let (code, out, _) = approved(&[
        "run",
        "--",
        "X={{keygent:new/tok}} sh -c 'printf \"%s\" \"$X\"'",
    ]);
    assert_eq!((code, out.as_str()), (0, "‹keygent:new/tok›"));
    // create-only: an existing handle is refused before anyone is asked to approve
    let mut x = cmd(&root, &["capture", "svc/key", "--", make]);
    x.current_dir(&proj);
    let o = x.output().unwrap();
    assert_eq!(
        (o.status.code(), String::from_utf8(o.stderr).unwrap().trim()),
        (
            Some(1),
            "keygent: this needs your passphrase — run it in your own terminal"
        )
    );
    // weak values and failed commands store nothing
    let (code, _, _) = approved(&["capture", "weak/one", "--", "echo short"]);
    assert_eq!(code, 1);
    let (code, _, _) = approved(&[
        "capture",
        "fail/one",
        "--",
        "echo abcdefghijklmnopqrstuvwxyz0123456789; exit 3",
    ]);
    assert_eq!(code, 3);
    let (_, out, _) = run(&root, &["ls"], &[]);
    assert!(
        !out.contains("weak/one") && !out.contains("fail/one"),
        "{out}"
    );
    // a capture whose command uses a secret needs approval, and the approval says where stdout goes
    let mut s = run_in(
        &root,
        &proj,
        &[
            "capture",
            "derived/one",
            "--",
            "X={{keygent:svc/key}} sh -c 'echo \"$X\"'",
        ],
    );
    s.expect(WAITING);
    let (_, out, _) = run(&root, &["pending"], &[]);
    assert!(
        out.contains("⚠ capture: stdout (trimmed) is stored as the new secret derived/one"),
        "{out}"
    );
    assert_eq!(run(&root, &["deny"], &[]).0, 0);
    assert_eq!(s.finish().0, 75);
    let (code, out, _) = run(&root, &["audit"], &[]);
    assert_eq!(code, 0);
    assert!(out.contains("\"event\":\"capture\""), "{out}");
    let (code, _, err) = run(&root, &["audit", "--verify"], &[]);
    assert_eq!(code, 0, "{err}");
}
