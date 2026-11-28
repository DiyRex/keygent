//! Claude Code hook end to end (SPEC §5.10, ADR 0001): the real binary as `keygent hook pre`, fed the PreToolUse JSON
//! that Claude Code 2.1.332 sends, then the rewritten command run the way the Bash tool would. Also
//! `integrate claude` against a settings file under the test root (never the developer's own `~/.claude`).
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

use std::io::Write;
use std::process::{Command, Stdio};

fn hook_pre(root: &Root, payload: &str) -> (i32, String, String) {
    hook_pre_with(root, &[], payload)
}

fn hook_pre_with(root: &Root, extra: &[&str], payload: &str) -> (i32, String, String) {
    let args: Vec<&str> = ["hook", "pre"]
        .iter()
        .copied()
        .chain(extra.iter().copied())
        .collect();
    let mut c = cmd(root, &args);
    let mut child = c.spawn().unwrap();
    // a usage error exits before reading stdin: a broken pipe here is fine
    let _ = child.stdin.take().unwrap().write_all(payload.as_bytes());
    let o = child.wait_with_output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8(o.stdout).unwrap(),
        String::from_utf8(o.stderr).unwrap(),
    )
}

fn payload(cmd: &str, cwd: &str) -> String {
    let esc = cmd.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{"session_id":"s1","prompt_id":"p1","transcript_path":"/tmp/t","cwd":"{cwd}","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{{"command":"{esc}","description":"make a droplet"}},"tool_use_id":"toolu_1"}}"#
    )
}

/// The `command` value inside `updatedInput` (our writer escapes only `"` and `\`, and launcher paths have neither).
fn rewritten(out: &str) -> String {
    let start = out.find(r#""updatedInput":{"command":""#).unwrap()
        + r#""updatedInput":{"command":""#.len();
    let rest = &out[start..];
    rest[..rest.find("\",\"").unwrap()]
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

#[test]
fn hook_rewrites_placeholder_commands_into_broker_grants() {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "do/token", &c).0, 0); // custody: no per-command prompt
    let proj = root.0.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    let cwd = proj.to_str().unwrap();
    let cmd_text = "T={{keygent:do/token}} sh -c 'printf \"%s\" \"$T\"'";

    // sealed: deny with keygent's line, no rewrite
    let (code, out, _) = hook_pre(&root, &payload(cmd_text, cwd));
    assert_eq!(code, 0);
    assert!(
        out.contains(r#""permissionDecision":"deny""#) && out.contains("keygent unseal"),
        "{out}"
    );

    assert_eq!(unseal(&root, &[]).0, 0);
    // a plain command: no output at all (zero tokens)
    let (code, out, err) = hook_pre(&root, &payload("ls -la", cwd));
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));

    // a placeholder command: rewritten to run --grant, other fields kept, no permission decision
    let (code, out, err) = hook_pre(&root, &payload(cmd_text, cwd));
    assert_eq!(code, 0, "{err}");
    assert!(
        !out.contains("permissionDecision") && out.contains(r#""description":"make a droplet""#),
        "{out}"
    );
    let new_cmd = rewritten(&out);
    assert!(
        new_cmd.contains(" run --grant ") && !new_cmd.contains("{{keygent"),
        "{new_cmd}"
    );
    assert!(!out.contains(&c) && !err.contains(&c));

    // run it the way the Bash tool would: the child holds only a dummy
    let o = Command::new("/bin/sh")
        .args(["-c", &new_cmd])
        .current_dir(&proj)
        .env_clear()
        .env("KEYGENT_TEST_ROOT", &root.0)
        .env("KEYGENT_TEST_FAST_KDF", "1")
        .env("HOME", &root.0)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let shown = String::from_utf8(o.stdout).unwrap();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        shown.len() == c.len() && shown != c,
        "dummy expected: {shown}"
    );
    // the grant is single use
    let o = Command::new("/bin/sh")
        .args(["-c", &new_cmd])
        .current_dir(&proj)
        .env_clear()
        .env("KEYGENT_TEST_ROOT", &root.0)
        .env("HOME", &root.0)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_ne!(o.status.code(), Some(0));
    assert_no_plaintext(&root, &c);
}

#[test]
fn integrate_installs_merges_and_removes_cleanly() {
    let root = Root::new();
    let dir = root.0.join(".claude");
    std::fs::create_dir_all(&dir).unwrap();
    let user = "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"deny\": [\n      \"Read(./.env)\"\n    ]\n  }\n}\n";
    std::fs::write(dir.join("settings.json"), user).unwrap();
    let (code, _, err) = run(&root, &["integrate", "claude"], &[]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("hook installed"), "{err}");
    let s = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert!(
        s.contains("\"onFailure\": \"continue\"") && !s.contains("\"if\""),
        "{s}"
    );
    assert!(s.starts_with("{\n  \"model\": \"opus\""), "{s}");
    assert_eq!(
        std::fs::read_to_string(dir.join("settings.json.keygent-backup")).unwrap(),
        user
    );
    let (code, _, _) = run(&root, &["integrate", "claude"], &[]);
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(dir.join("settings.json")).unwrap(),
        s,
        "idempotent"
    );
    let (code, _, _) = run(&root, &["integrate", "claude", "--remove"], &[]);
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(dir.join("settings.json")).unwrap(),
        user,
        "remove restores the file"
    );
    // invalid JSON is left untouched
    std::fs::write(dir.join("settings.json"), "{ nope").unwrap();
    let (code, _, err) = run(&root, &["integrate", "claude"], &[]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("isn't valid JSON"), "{err}");
    assert_eq!(
        std::fs::read_to_string(dir.join("settings.json")).unwrap(),
        "{ nope"
    );
}

/// `--chain` arg for a one-hook group running `sh -c <script>` (the shape `integrate claude` writes).
fn chain_arg(script: &str) -> String {
    let esc = script.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{"at":0,"group":{{"matcher":"Bash|bash","hooks":[{{"type":"command","command":"{esc}"}}]}}}}"#
    )
}

#[test]
fn chained_hooks_run_after_keygent_and_cannot_drop_its_rewrite() {
    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "do/token", &c).0, 0);
    assert_eq!(unseal(&root, &[]).0, 0);
    let proj = root.0.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    let cwd = proj.to_str().unwrap();
    let seen = root.0.join("seen.json");
    let cmd_text = "T={{keygent:do/token}} sh -c 'printf \"%s\" \"$T\"'";

    // a lean-ctx-like hook: records what it was given, allows, and tries to swap in the original command
    let rogue = format!(
        r#"cat > '{}'; printf '%s' '{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow","additionalContext":"chained ran","updatedInput":{{"command":"echo replaced"}}}}}}'"#,
        seen.display()
    );
    let chain = chain_arg(&rogue);
    let (code, out, err) = hook_pre_with(&root, &["--chain", &chain], &payload(cmd_text, cwd));
    assert_eq!(code, 0, "{err}");
    let given = std::fs::read_to_string(&seen).unwrap();
    assert!(
        given.contains(" run --grant ") && !given.contains("{{keygent") && !given.contains(&c),
        "the chained hook sees keygent's rewrite, never the placeholder or a value: {given}"
    );
    let new_cmd = rewritten(&out);
    assert!(
        new_cmd.contains(" run --grant "),
        "a rewrite that drops keygent's is ignored: {out}"
    );
    assert!(
        out.contains(r#""permissionDecision":"allow""#) && out.contains("chained ran"),
        "{out}"
    );
    assert!(!out.contains(&c) && !err.contains(&c));

    // a chained exit 2 blocks the call, with the hook's stderr
    let chain = chain_arg("cat >/dev/null; echo 'no droplets today' >&2; exit 2");
    let (code, out, err) = hook_pre_with(&root, &["--chain", &chain], &payload("ls", cwd));
    assert_eq!((code, out.as_str()), (2, ""), "{err}");
    assert!(err.contains("no droplets today"), "{err}");

    // a broken chained hook is skipped; keygent's rewrite still applies
    let chain = chain_arg("exit 1");
    let (code, out, err) = hook_pre_with(&root, &["--chain", &chain], &payload(cmd_text, cwd));
    assert_eq!(code, 0, "{err}");
    assert!(rewritten(&out).contains(" run --grant "), "{out}");

    // a malformed --chain is a usage error, not a silent pass
    let (code, _, _) = hook_pre_with(&root, &["--chain", "{nope"], &payload("ls", cwd));
    assert_eq!(code, 64);
    assert_no_plaintext(&root, &c);
}

#[test]
fn integrate_chains_a_co_installed_bash_hook_and_restores_it() {
    let root = Root::new();
    let dir = root.0.join(".claude");
    std::fs::create_dir_all(&dir).unwrap();
    let user = "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash|bash\",\n        \"hooks\": [\n          {\n            \"command\": \"/opt/homebrew/bin/lean-ctx hook rewrite\",\n            \"type\": \"command\"\n          }\n        ]\n      }\n    ]\n  }\n}\n";
    std::fs::write(dir.join("settings.json"), user).unwrap();
    let (code, _, err) = run(&root, &["integrate", "claude"], &[]);
    assert_eq!(code, 0, "{err}");
    let s = std::fs::read_to_string(dir.join("settings.json")).unwrap();
    assert_eq!(
        s.matches("\"matcher\"").count(),
        1,
        "lean-ctx moved behind keygent: {s}"
    );
    assert!(
        s.contains("\"--chain\"")
            && s.contains("lean-ctx hook rewrite")
            && s.contains("\"timeout\": 70"),
        "{s}"
    );
    let (code, _, _) = run(&root, &["integrate", "claude"], &[]);
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(dir.join("settings.json")).unwrap(),
        s,
        "idempotent"
    );
    let (code, _, _) = run(&root, &["integrate", "claude", "--remove"], &[]);
    assert_eq!(code, 0);
    assert_eq!(
        std::fs::read_to_string(dir.join("settings.json")).unwrap(),
        user,
        "lean-ctx restored exactly"
    );
}
