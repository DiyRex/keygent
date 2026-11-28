#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests: a panic is the failure report"
)]
use super::*;

const GRANT: &str = "'/k/keygent' run --grant ab12";

fn input(cmd: &str) -> Value {
    let mut v = json::parse(
        br#"{"cwd":"/p","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"","description":"d"}}"#,
    )
    .unwrap();
    v.get_mut("tool_input")
        .unwrap()
        .set("command", Value::str(cmd));
    v
}

fn ok_grant(_: &str, _: &str) -> Result<String> {
    Ok(GRANT.to_owned())
}

fn ran(code: i32, stdout: &str) -> Option<Ran> {
    Some(Ran {
        code: Some(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: b"blocked by policy".to_vec(),
    })
}

fn cmd_of(out: &Out) -> Option<String> {
    let Out::Json(Some(v)) = out else { return None };
    let c = v
        .get("hookSpecificOutput")?
        .get("updatedInput")?
        .get("command")?;
    c.as_str().map(str::to_owned)
}

/// A lean-ctx-like hook: allow, and wrap whatever command it was given.
fn wrapper(_: &Value, payload: &str) -> Option<Ran> {
    let p = json::parse(payload.as_bytes()).unwrap();
    let c = p
        .get("tool_input")
        .unwrap()
        .get("command")
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let mut ti = p.get("tool_input").unwrap().clone();
    ti.set(
        "command",
        Value::Str(format!("lean-ctx -c {}", sh_quote(&c))),
    );
    let out = Value::Obj(vec![
        (
            "hookSpecificOutput".into(),
            Value::Obj(vec![
                ("hookEventName".into(), Value::str("PreToolUse")),
                ("permissionDecision".into(), Value::str("allow")),
                ("updatedInput".into(), ti),
            ]),
        ),
        ("modifiedArgs".into(), Value::str("echo replaced")),
        ("systemMessage".into(), Value::str("wrapped")),
    ]);
    ran(0, &out.compact())
}

fn hook() -> Vec<Value> {
    vec![json::parse(br#"{"type":"command","command":"x"}"#).unwrap()]
}

#[test]
fn plain_commands_produce_nothing_without_a_chain() {
    let i = input("ls -la");
    let own = own_step(&i, |_, _| panic!("no grant for a plain command"));
    assert_eq!(compose(&i, own, &[], &mut |_, _| panic!()), Out::Json(None));
    let mut other = i.clone();
    other.set("tool_name", Value::str("Read"));
    assert!(matches!(own_step(&other, ok_grant), Own::Pass));
}

#[test]
fn placeholder_is_rewritten_with_no_decision_of_its_own() {
    let i = input("T={{keygent:do/token}} doctl compute droplet create x");
    let out = compose(&i, own_step(&i, ok_grant), &[], &mut |_, _| panic!());
    assert_eq!(cmd_of(&out).as_deref(), Some(GRANT));
    let Out::Json(Some(v)) = out else { panic!() };
    let hso = v.get("hookSpecificOutput").unwrap();
    assert!(hso.get("permissionDecision").is_none());
    assert_eq!(
        hso.get("updatedInput").unwrap().get("description"),
        Some(&Value::str("d"))
    );
}

#[test]
fn keygent_refusal_is_a_deny_and_chained_hooks_never_run() {
    let i = input("echo {{keygent:a/b}}");
    let own = own_step(&i, |_, _| Err(Error::Sealed));
    let out = compose(&i, own, &hook(), &mut |_, _| panic!("chain must not run"));
    let Out::Json(Some(v)) = out else { panic!() };
    let s = v.compact();
    assert!(
        s.contains(r#""permissionDecision":"deny""#) && s.contains("keygent unseal"),
        "{s}"
    );
    let mut no_cwd = i.clone();
    if let Value::Obj(m) = &mut no_cwd {
        m.retain(|(k, _)| k != "cwd");
    }
    assert!(matches!(own_step(&no_cwd, ok_grant), Own::Deny(_)));
}

#[test]
fn chained_rewriter_wraps_keygents_command_not_the_original() {
    let i = input("T={{keygent:a/b}} curl x");
    let out = compose(&i, own_step(&i, ok_grant), &hook(), &mut wrapper);
    assert_eq!(
        cmd_of(&out).unwrap(),
        format!("lean-ctx -c {}", sh_quote(GRANT))
    );
    let Out::Json(Some(v)) = out else { panic!() };
    assert_eq!(
        v.get("hookSpecificOutput")
            .unwrap()
            .get("permissionDecision"),
        Some(&Value::str("allow"))
    );
    assert_eq!(
        v.get("systemMessage"),
        Some(&Value::str("wrapped")),
        "documented common fields pass through"
    );
    assert_eq!(
        v.get("modifiedArgs"),
        None,
        "undocumented ones (which can carry a command) don't"
    );
    // a plain command still reaches the chained hook, which sees the original
    let i = input("git status");
    let out = compose(&i, own_step(&i, ok_grant), &hook(), &mut wrapper);
    assert_eq!(cmd_of(&out).unwrap(), "lean-ctx -c 'git status'");
}

#[test]
fn chained_rewrite_that_drops_keygents_command_is_ignored() {
    let i = input("T={{keygent:a/b}} curl x");
    let mut drop = |_: &Value, _: &str| {
        ran(
            0,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{"command":"T={{keygent:a/b}} curl x"}}}"#,
        )
    };
    let out = compose(&i, own_step(&i, ok_grant), &hook(), &mut drop);
    assert_eq!(cmd_of(&out).as_deref(), Some(GRANT));
}

#[test]
fn decisions_combine_deny_over_ask_over_allow() {
    let i = input("ls");
    let two = [hook(), hook()].concat();
    let mut n = 0;
    let mut seq = |_: &Value, _: &str| {
        n += 1;
        let d = if n == 1 { "ask" } else { "allow" };
        ran(
            0,
            &format!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"{d}","additionalContext":"c{n}"}}}}"#
            ),
        )
    };
    let Out::Json(Some(v)) = compose(&i, Own::Pass, &two, &mut seq) else {
        panic!()
    };
    let hso = v.get("hookSpecificOutput").unwrap();
    assert_eq!(hso.get("permissionDecision"), Some(&Value::str("ask")));
    assert_eq!(hso.get("additionalContext"), Some(&Value::str("c1\nc2")));
    let mut deny_then = |_: &Value, _: &str| {
        ran(
            0,
            r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"no"}}"#,
        )
    };
    let Out::Json(Some(v)) = compose(&i, Own::Pass, &two, &mut deny_then) else {
        panic!()
    };
    assert_eq!(
        v.get("hookSpecificOutput")
            .unwrap()
            .get("permissionDecision"),
        Some(&Value::str("deny"))
    );
}

#[test]
fn chained_failures_skip_unless_block_and_exit_2_blocks() {
    let i = input("ls");
    assert_eq!(
        compose(&i, Own::Pass, &hook(), &mut |_, _| ran(1, "junk")),
        Out::Json(None)
    );
    assert_eq!(
        compose(&i, Own::Pass, &hook(), &mut |_, _| None),
        Out::Json(None)
    );
    assert_eq!(
        compose(&i, Own::Pass, &hook(), &mut |_, _| ran(0, "not json")),
        Out::Json(None)
    );
    assert_eq!(
        compose(&i, Own::Pass, &hook(), &mut |_, _| ran(2, "")),
        Out::Block("blocked by policy".into())
    );
    let strict =
        vec![json::parse(br#"{"type":"command","command":"x","onFailure":"block"}"#).unwrap()];
    assert!(matches!(
        compose(&i, Own::Pass, &strict, &mut |_, _| None),
        Out::Block(_)
    ));
}

#[test]
fn run_spec_runs_exec_and_shell_forms_with_payload_on_stdin() {
    let sh = json::parse(br#"{"type":"command","command":"cat; echo; exit 3"}"#).unwrap();
    let r = run_spec(&sh, "{\"a\":1}").unwrap();
    assert_eq!(
        (r.code, r.stdout.as_slice()),
        (Some(3), &b"{\"a\":1}\n"[..])
    );
    let exec =
        json::parse(br#"{"type":"command","command":"/bin/echo","args":["a b","$HOME"]}"#).unwrap();
    let r = run_spec(&exec, "").unwrap();
    assert_eq!(r.stdout, b"a b $HOME\n");
    let slow =
        json::parse(br#"{"type":"command","command":"sleep 5; sleep 5","timeout":1}"#).unwrap();
    let t = Instant::now();
    assert!(run_spec(&slow, "").is_none());
    assert!(t.elapsed() < Duration::from_secs(4));
}

#[test]
fn sh_quote_survives_single_quotes() {
    assert_eq!(sh_quote("/a b/it's"), r"'/a b/it'\''s'");
}
