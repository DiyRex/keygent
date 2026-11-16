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
    clippy::type_complexity
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
            if path.is_dir() {
                walk(&path, c);
            } else {
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
