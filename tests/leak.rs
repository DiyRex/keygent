//! Leak suite, Phase 2 part (SPEC §11): adversarial commands through the **real** broker `run` path, with a fresh
//! canary per test. The canary must never reach the agent in any form it could decode: stdout or stderr as raw bytes,
//! UTF-16LE, base64 (std and url, every byte alignment) or hex (both cases). It must also never reach the audit log,
//! the broker log, or any file under the test root other than the vault (which holds it encrypted).
//!
//! Cases are tagged with the attacker tier (docs/THREATS.md). `known-gap` cases assert the **documented** behaviour of a
//! THREATS "Known gaps" item instead of prevention, so a change in that behaviour shows up here.
//!
//! Hook-path cases (forged `hook pre`, Read/Write tools, observer chain, prompts, PostToolUse) land with Phase 3.
//! Cases already covered elsewhere: changed program after approval, approved script edited before exec, runtime and
//! output limits, crash leftovers, fake broker squat, audit unwritable, manifest trust and reserved env names
//! (`tests/cli.rs`); grant queue and auth-failure floods (`src/broker/limits.rs`, `src/broker/grant.rs` unit tests).
//!
//! Run with `cargo test --features test-profile --test leak`.
#![cfg(feature = "test-profile")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests: a panic is the failure report"
)]

mod common;
use common::*;

use std::path::Path;
use std::process::Command;

// ------------------------------------------------------------------ encodings an agent could decode

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64 characters fully determined by `v` when it starts at byte offset `k` of a larger stream.
fn b64_core(v: &[u8], k: usize, alpha: &[u8; 64]) -> String {
    let mut bits = vec![0u8; k];
    bits.extend_from_slice(v);
    let mut full = Vec::new();
    for c in bits.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for s in [18u32, 12, 6, 0] {
            full.push(alpha[((n >> s) & 63) as usize]);
        }
    }
    let first = (k * 8).div_ceil(6);
    let last = (k * 8 + v.len() * 8) / 6;
    String::from_utf8(full[first..last].to_vec()).unwrap()
}

/// (name, bytes) for every form checked.
fn forms(c: &str) -> Vec<(String, Vec<u8>)> {
    let v = c.as_bytes();
    let mut f = vec![("raw".to_owned(), v.to_vec())];
    f.push((
        "utf16le".into(),
        v.iter().flat_map(|&b| [b, 0]).collect::<Vec<u8>>(),
    ));
    for k in 0..3 {
        f.push((
            format!("base64 k={k}"),
            b64_core(v, k, B64_STD).into_bytes(),
        ));
        f.push((
            format!("base64url k={k}"),
            b64_core(v, k, B64_URL).into_bytes(),
        ));
    }
    let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
    f.push(("hex".into(), hex.clone().into_bytes()));
    f.push(("HEX".into(), hex.to_uppercase().into_bytes()));
    f
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Name of the first form of `c` found in `hay`.
fn leaked_form(hay: &[u8], c: &str) -> Option<String> {
    forms(c)
        .into_iter()
        .find(|(_, b)| contains(hay, b))
        .map(|(n, _)| n)
}

// ------------------------------------------------------------------ helpers

/// POSIX single-quote a shell body.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A tool the child can reach on the broker's PATH (`/usr/bin:/bin` under the tests' cleared env).
fn have(tool: &str) -> bool {
    ["/usr/bin", "/bin"]
        .iter()
        .any(|d| Path::new(d).join(tool).exists())
}

/// Run `cmd` through `keygent run`, approve it, return (exit, stdout + stderr bytes).
fn approved_run(root: &Root, proj: &Path, cmd: &str) -> (i32, Vec<u8>) {
    let mut s = run_in(root, proj, &["run", "--", cmd]);
    s.expect(WAITING);
    approve(root);
    let (code, out, err) = s.finish();
    let mut all = out.into_bytes();
    all.extend_from_slice(err.as_bytes());
    (code, all)
}

struct Case {
    name: &'static str,
    tier: &'static str,
    /// Shell body run with the canary in `$X` (and the PEM in `$P` for multi-line cases).
    body: &'static str,
    needs: &'static [&'static str],
    /// `Some(reason)`: THREATS known gap; the test asserts the leak is visible (documented), not prevented.
    known_gap: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        name: "echo",
        tier: "T1",
        body: r#"echo "$X""#,
        needs: &[],
        known_gap: None,
    },
    Case {
        name: "printf no newline",
        tier: "T1",
        body: r#"printf %s "$X""#,
        needs: &[],
        known_gap: None,
    },
    Case {
        name: "env dump",
        tier: "T1",
        body: "env",
        needs: &["env"],
        known_gap: None,
    },
    Case {
        name: "printenv",
        tier: "T1",
        body: "printenv X",
        needs: &["printenv"],
        known_gap: None,
    },
    Case {
        name: "export -p",
        tier: "T1",
        body: "export -p",
        needs: &[],
        known_gap: None,
    },
    Case {
        name: "set",
        tier: "T1",
        body: "set",
        needs: &[],
        known_gap: None,
    },
    Case {
        name: "ps eww",
        tier: "T2",
        body: "ps eww -p $$",
        needs: &["ps"],
        known_gap: None,
    },
    Case {
        name: "/proc/self/environ",
        tier: "T2",
        body: "test -r /proc/self/environ && tr '\\0' '\\n' < /proc/self/environ",
        needs: &["tr"],
        known_gap: None,
    },
    Case {
        name: "python os.environ",
        tier: "T2",
        body: r#"python3 -c 'import os; print(os.environ["X"])'"#,
        needs: &["python3"],
        known_gap: None,
    },
    Case {
        name: "perl %ENV",
        tier: "T2",
        body: r#"perl -e 'print $ENV{X}'"#,
        needs: &["perl"],
        known_gap: None,
    },
    Case {
        name: "awk ENVIRON",
        tier: "T2",
        body: r#"awk 'BEGIN { print ENVIRON["X"] }'"#,
        needs: &["awk"],
        known_gap: None,
    },
    Case {
        name: "base64 offset 0",
        tier: "T2",
        body: r#"printf %s "$X" | base64"#,
        needs: &["base64"],
        known_gap: None,
    },
    Case {
        name: "base64 offset 1",
        tier: "T2",
        body: r#"printf 'a%s' "$X" | base64"#,
        needs: &["base64"],
        known_gap: None,
    },
    Case {
        name: "base64 offset 2",
        tier: "T2",
        body: r#"printf 'ab%s' "$X" | base64"#,
        needs: &["base64"],
        known_gap: None,
    },
    Case {
        name: "base64url",
        tier: "T2",
        body: r#"python3 -c 'import os,base64; print(base64.urlsafe_b64encode(b"q" + os.environ["X"].encode()).decode())'"#,
        needs: &["python3"],
        known_gap: None,
    },
    Case {
        name: "hex (od)",
        tier: "T2",
        body: r#"printf %s "$X" | od -An -tx1 | tr -d ' \n'"#,
        needs: &["od", "tr"],
        known_gap: None,
    },
    Case {
        name: "HEX upper",
        tier: "T2",
        body: r#"printf %s "$X" | od -An -tx1 | tr -d ' \n' | tr a-f A-F"#,
        needs: &["od", "tr"],
        known_gap: None,
    },
    Case {
        name: "json.dumps",
        tier: "T2",
        body: r#"python3 -c 'import os,json; print(json.dumps({"k": os.environ["X"]}))'"#,
        needs: &["python3"],
        known_gap: None,
    },
    Case {
        name: "percent-encoded",
        tier: "T2",
        body: r#"python3 -c 'import os,urllib.parse as u; print(u.quote(os.environ["X"], safe=""))'"#,
        needs: &["python3"],
        known_gap: None,
    },
    Case {
        name: "UTF-16LE",
        tier: "T2",
        body: r#"printf %s "$X" | iconv -f UTF-8 -t UTF-16LE"#,
        needs: &["iconv"],
        known_gap: None,
    },
    Case {
        name: "split across flushes",
        tier: "T2",
        body: r#"python3 -c 'import os,sys,time; x=os.environ["X"]; sys.stdout.write(x[:13]); sys.stdout.flush(); time.sleep(0.3); sys.stdout.write(x[13:] + "\n")'"#,
        needs: &["python3"],
        known_gap: None,
    },
    Case {
        name: "byte-by-byte drip",
        tier: "T2",
        body: r#"python3 -c 'import os,sys,time
for ch in os.environ["X"]:
    sys.stdout.write(ch); sys.stdout.flush(); time.sleep(0.005)'"#,
        needs: &["python3"],
        known_gap: None,
    },
    Case {
        name: "stderr",
        tier: "T1",
        body: r#"printf '%s\n' "$X" >&2"#,
        needs: &[],
        known_gap: None,
    },
    Case {
        name: "background survivor",
        tier: "T2",
        body: r#"(sleep 0.5; printf '%s\n' "$X") & echo started"#,
        needs: &["sleep"],
        known_gap: None,
    },
    Case {
        name: "multi-line value, one line",
        tier: "T2",
        body: r#"printf '%s\n' "$P" | sed -n 2p"#,
        needs: &["sed"],
        known_gap: None,
    },
    Case {
        name: "multi-line value, body unwrapped",
        tier: "T2",
        body: r#"printf '%s\n' "$P" | grep -v -- ----- | tr -d '\n'"#,
        needs: &["grep", "tr"],
        known_gap: None,
    },
    Case {
        name: "reversed",
        tier: "T2",
        body: r#"printf '%s\n' "$X" | rev"#,
        needs: &["rev"],
        known_gap: Some(
            "THREATS gap 8: an approved command can transform the value (here: reversed)",
        ),
    },
    Case {
        name: "split across stdout and stderr",
        tier: "T2",
        body: r#"printf %s "$X" | cut -c1-20; printf %s "$X" | cut -c21- >&2"#,
        needs: &["cut"],
        known_gap: Some("THREATS gap 8: halves on different streams are never one match"),
    },
];

/// Every case through the broker with approval; then no canary in any log or file under the root.
#[test]
fn adversarial_commands_never_show_the_value() {
    let (root, c, proj) = run_setup();
    // a PEM-shaped multi-line value: armor + two strong lines
    let (l1, l2) = (canary(), canary());
    let pem = format!("-----BEGIN KEY-----\n{l1}\n{l2}\n-----END KEY-----");
    let mut lines = vec![PASS];
    lines.extend(pem.lines());
    lines.push(".");
    let (code, _, err) = run(&root, &["add", "svc/pem", "--multiline"], &lines);
    assert_eq!(code, 0, "{err}");

    // control: the child really holds the value (an empty $X would make every case pass trivially)
    let (code, out) = approved_run(
        &root,
        &proj,
        "X={{keygent:svc/key}} sh -c 'printf %s \"$X\" | wc -c; printf %s \"$X\"'",
    );
    let shown = String::from_utf8_lossy(&out);
    assert_eq!(code, 0, "{shown}");
    assert!(
        shown.trim_start().starts_with(&c.len().to_string()),
        "{shown}"
    );
    assert!(shown.contains("‹keygent:svc/key›"), "{shown}");

    let mut ran = 0;
    for case in CASES {
        if let Some(t) = case.needs.iter().find(|t| !have(t)) {
            eprintln!("skip {:?}: {t} not installed", case.name);
            continue;
        }
        let cmd = format!(
            "X={{{{keygent:svc/key}}}} P={{{{keygent:svc/pem}}}} sh -c {}",
            sq(case.body)
        );
        let (code, out) = approved_run(&root, &proj, &cmd);
        ran += 1;
        let hit = leaked_form(&out, &c)
            .or_else(|| leaked_form(&out, &l1).map(|f| format!("pem line 1 {f}")))
            .or_else(|| leaked_form(&out, &l2).map(|f| format!("pem line 2 {f}")));
        let shown = String::from_utf8_lossy(&out);
        match case.known_gap {
            None => assert!(
                hit.is_none(),
                "[{}] {:?} leaked ({}) exit {code}: {shown}",
                case.tier,
                case.name,
                hit.unwrap_or_default()
            ),
            Some(why) => {
                // documented: the value is recoverable from the output, but never verbatim
                assert!(
                    hit.is_none(),
                    "[{}] {:?} leaked verbatim: {shown}",
                    case.tier,
                    case.name
                );
                let joined = shown.replace(['\n', '\r'], "");
                let reversed: String = c.chars().rev().collect();
                assert!(
                    joined.contains(&reversed)
                        || joined.contains(&c[20..])
                        || joined.contains(&c[..20]),
                    "[{}] {:?} known gap no longer reproduces ({why}) — update THREATS: {shown}",
                    case.tier,
                    case.name
                );
            }
        }
    }
    assert!(ran >= 15, "only {ran} cases ran; install the missing tools");

    // background survivors were killed with the run's session
    std::thread::sleep(std::time::Duration::from_millis(800));
    // nothing in the audit log, broker log or any other file under the root
    assert_no_plaintext(&root, &c);
    assert_no_plaintext(&root, &l1);
    assert_no_plaintext(&root, &l2);
}

/// `{{keygent-file:h}}`: the child gets a path; the path never contains the value, reading it is redacted.
#[test]
fn file_binding_path_never_holds_the_value() {
    let (root, c, proj) = run_setup();
    let (_, out) = approved_run(
        &root,
        &proj,
        "F={{keygent-file:svc/key}} sh -c 'echo \"path=$F\"; cat \"$F\"; echo'",
    );
    let shown = String::from_utf8_lossy(&out);
    assert!(shown.contains("path=/"), "{shown}");
    assert!(leaked_form(&out, &c).is_none(), "{shown}");
    assert!(shown.contains("‹keygent:svc/key›"), "{shown}");
    assert_no_plaintext(&root, &c);
}

/// T2: data the agent pipes into `keygent run` never reaches the approved child (stdin is /dev/null).
#[test]
fn agent_stdin_never_reaches_the_child() {
    let (root, _c, proj) = run_setup();
    let mut s = run_in(
        &root,
        &proj,
        &["run", "--", "X={{keygent:svc/key}} sh -c 'cat; echo done'"],
    );
    s.send("AGENT_INPUT_LINE");
    s.expect(WAITING);
    approve(&root);
    let (code, out, _) = s.finish();
    assert_eq!((code, out.as_str()), (0, "done\n"));
}

fn request_id(root: &Root) -> String {
    let (_, out, _) = run(root, &["pending"], &[]);
    out.lines()
        .find_map(|l| l.strip_prefix("request "))
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("no request in: {out}"))
}

/// T2: a consumed grant can't be replayed, and an invented grant id gets nothing.
#[test]
fn grants_are_single_use_and_unguessable() {
    let (root, c, proj) = run_setup();
    let mut s = run_in(
        &root,
        &proj,
        &["run", "--", "X={{keygent:svc/key}} sh -c 'echo ran'"],
    );
    s.expect(WAITING);
    let id = request_id(&root);
    approve(&root);
    let (code, out, _) = s.finish();
    assert_eq!((code, out.as_str()), (0, "ran\n"));
    for forged in [id.clone(), "00".repeat(id.len() / 2)] {
        let mut r = run_in(&root, &proj, &["run", "--grant", &forged]);
        let (code, out, err) = {
            drop(r.stdin.take());
            r.finish()
        };
        assert_ne!(code, 0, "grant {forged} ran again: {out}");
        assert!(!out.contains("ran") && !out.contains(&c), "{out}");
        assert!(err.starts_with("keygent: "), "{err}");
    }
}

/// T2: a wrong passphrase never approves; the request is still pending and the command never ran.
#[test]
fn forged_approval_never_runs() {
    let (root, _c, proj) = run_setup();
    let marker = proj.join("ran.txt");
    let mut s = run_in(
        &root,
        &proj,
        &[
            "run",
            "--",
            "X={{keygent:svc/key}} sh -c 'echo x > ran.txt'",
        ],
    );
    s.expect(WAITING);
    let (code, _, err) = run(&root, &["approve"], &["not-the-passphrase-at-all"]);
    assert_ne!(code, 0, "{err}");
    assert!(request_id(&root).len() >= 16);
    assert_eq!(run(&root, &["deny"], &[]).0, 0);
    let (code, _, _) = s.finish();
    assert_ne!(code, 0);
    assert!(!marker.exists(), "denied command ran");
}

/// T2: control, ANSI and bidi characters in a command are shown escaped in the approval, never raw.
#[test]
fn approval_display_escapes_spoofing_characters() {
    let (root, _c, proj) = run_setup();
    let cmd =
        "X={{keygent:svc/key}} sh -c 'echo safe' # \u{1b}[2K\u{1b}[1A\u{202e}gnp.txt \u{200b}";
    let mut s = run_in(&root, &proj, &["run", "--", cmd]);
    s.expect(WAITING);
    let (_, out, _) = run(&root, &["pending"], &[]);
    for raw in ['\u{1b}', '\u{202e}', '\u{200b}'] {
        assert!(!out.contains(raw), "raw {raw:?} in approval: {out:?}");
    }
    assert!(
        out.contains("\\u{1b}") && out.contains("\\u{202e}"),
        "{out}"
    );
    assert_eq!(run(&root, &["deny"], &[]).0, 0);
    let _ = s.finish();
}

/// T2: a script with a benign head and the exfiltration at line 300 is shown in full before approval.
#[test]
fn long_script_is_shown_in_full() {
    let (root, _c, proj) = run_setup();
    let mut body = String::from("#!/bin/sh\n");
    for i in 1..299 {
        body.push_str(&format!("echo line {i} >/dev/null\n"));
    }
    body.push_str("printf '%s' \"$X\" > /dev/null # EXFIL_AT_LINE_300\n");
    std::fs::write(proj.join("deploy.sh"), body).unwrap();
    let mut s = run_in(
        &root,
        &proj,
        &["run", "--", "X={{keygent:svc/key}} sh ./deploy.sh"],
    );
    s.expect(WAITING);
    let (_, out, _) = run(&root, &["pending"], &[]);
    assert!(out.contains("EXFIL_AT_LINE_300"), "line 300 not shown");
    assert_eq!(run(&root, &["deny"], &[]).0, 0);
    let _ = s.finish();
}

/// T2: the client's environment can't steer the run (a fake `sh` first on the client's PATH is never used).
#[test]
fn client_environment_is_ignored() {
    let (root, c, proj) = run_setup();
    let evil = root.0.join("evil");
    std::fs::create_dir_all(&evil).unwrap();
    let fake = evil.join("sh");
    std::fs::write(&fake, "#!/bin/sh\necho EVIL_SHELL \"$X\"\n").unwrap();
    std::os::unix::fs::PermissionsExt::set_mode(
        &mut std::fs::metadata(&fake).unwrap().permissions(),
        0o755,
    );
    Command::new("chmod")
        .args(["755"])
        .arg(&fake)
        .status()
        .unwrap();
    let mut cmd = common::cmd(
        &root,
        &["run", "--", "X={{keygent:svc/key}} sh -c 'echo real'"],
    );
    cmd.current_dir(&proj)
        .env("PATH", format!("{}:/usr/bin:/bin", evil.display()))
        .env("X", "client-value")
        .env("BASH_ENV", fake.as_os_str())
        .env("ENV", fake.as_os_str());
    let mut s = Session::start_cmd(cmd);
    s.expect(WAITING);
    approve(&root);
    let (code, out, err) = s.finish();
    assert_eq!((code, out.as_str()), (0, "real\n"), "{err}");
    assert!(!out.contains("EVIL") && !out.contains(&c));
}

/// T2: a copied vault file is useless on another machine — the passphrase alone can't open it without the device pepper.
#[test]
fn copied_vault_without_pepper_does_not_open() {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "svc/key", &c).0, 0);
    let other = Root::new();
    std::fs::create_dir_all(other.data()).unwrap();
    for e in std::fs::read_dir(root.data()).unwrap().flatten() {
        if e.path().is_file() {
            std::fs::copy(e.path(), other.data().join(e.file_name())).unwrap();
        }
    }
    let (code, out, err) = run(&other, &["reveal", "svc/key"], &[PASS]);
    assert_ne!(code, 0, "copied vault opened: {err}");
    assert!(!out.contains(&c) && !err.contains(&c));
}

/// Harness self-check: the detector finds the canary in real tool output when keygent is **not** in the path, so a
/// passing case above means the broker redacted it, not that the check is blind.
#[test]
fn harness_detects_every_encoding() {
    let c = canary();
    let mut checked = 0;
    for (tool, script) in [
        ("base64", r#"printf %s "$X" | base64"#),
        ("base64", r#"printf 'a%s' "$X" | base64"#),
        ("base64", r#"printf 'ab%s' "$X" | base64"#),
        ("od", r#"printf %s "$X" | od -An -tx1 | tr -d ' \n'"#),
        (
            "od",
            r#"printf %s "$X" | od -An -tx1 | tr -d ' \n' | tr a-f A-F"#,
        ),
        ("iconv", r#"printf %s "$X" | iconv -f UTF-8 -t UTF-16LE"#),
        (
            "python3",
            r#"python3 -c 'import os,base64; print(base64.urlsafe_b64encode(b"q" + os.environ["X"].encode()).decode())'"#,
        ),
    ] {
        if !have(tool) {
            continue;
        }
        let out = Command::new("/bin/sh")
            .args(["-c", script])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("X", &c)
            .output()
            .unwrap();
        assert!(
            leaked_form(&out.stdout, &c).is_some(),
            "detector blind to: {script}"
        );
        checked += 1;
    }
    assert!(checked >= 5, "only {checked} encodings checked");
}
