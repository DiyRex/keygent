//! `keygent hook pre [--chain '<hook json>']…`: Claude Code `PreToolUse` for `Bash` (SPEC §5.10, ADR 0001 as verified
//! 2026-11-28 on 2.1.332, ADR 0002 chaining).
//!
//! - A command containing `{{keygent:…}}` is handed to the broker as a grant and rewritten to
//!   `'<keygent>' run --grant <id>`; every other `tool_input` field is kept. keygent returns no `permissionDecision`
//!   of its own, so the user's rules still judge the command the agent asked for. A refusal (sealed vault, policy) is a
//!   `deny` with keygent's one-line reason. The hook never sees a value: it only forwards command text to the broker.
//! - **keygent goes first** (ADR 0002). Claude Code runs matching hooks in parallel and keeps only one `updatedInput`
//!   (observed with lean-ctx, 2026-11-28), so other Bash `PreToolUse` hooks are moved behind keygent by
//!   `integrate claude` and run here, in order, on the already rewritten input. A chained hook may wrap keygent's command
//!   (lean-ctx: `lean-ctx -c '…'`) but a rewrite that drops it is ignored. Decisions combine deny > ask > allow; a
//!   chained exit 2 blocks; a chained failure is skipped unless that hook said `onFailure: block`.
//! - Commands without a placeholder produce no output of keygent's own (zero tokens); chained hooks still run.

use super::grants::create_grant;
use crate::crypto::hex;
use crate::error::{Error, Result};
use crate::hook::json::{self, Value};
use crate::platform::{self, ipc};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHAIN_TIMEOUT_DEFAULT: u64 = 60;
const CHAIN_TIMEOUT_MAX: u64 = 600;
/// Top-level hook output fields Claude Code documents for every event (hooks reference, checked on 2.1.332).
const COMMON_FIELDS: [&str; 4] = ["continue", "stopReason", "suppressOutput", "systemMessage"];

/// Single-quote for POSIX `sh`.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn deny(reason: &str) -> Value {
    Value::Obj(vec![(
        "hookSpecificOutput".into(),
        Value::Obj(vec![
            ("hookEventName".into(), Value::str("PreToolUse")),
            ("permissionDecision".into(), Value::str("deny")),
            ("permissionDecisionReason".into(), Value::str(reason)),
        ]),
    )])
}

/// keygent's own step.
enum Own {
    /// Not a keygent command: nothing to change.
    Pass,
    /// Rewritten `tool_input`, and its `run --grant <id>` part (a chained rewrite must keep it).
    Rewrite(Value, String),
    Deny(Value),
}

fn own_step(input: &Value, grant: impl FnOnce(&str, &str) -> Result<String>) -> Own {
    if input.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return Own::Pass;
    }
    let Some(tool_input) = input.get("tool_input") else {
        return Own::Pass;
    };
    let Some(command) = tool_input.get("command").and_then(Value::as_str) else {
        return Own::Pass;
    };
    if !command.contains("{{keygent:") && !command.contains("{{keygent-file:") {
        return Own::Pass;
    }
    let Some(cwd) = input.get("cwd").and_then(Value::as_str) else {
        return Own::Deny(deny("keygent: hook input has no cwd — update Claude Code"));
    };
    match grant(command, cwd) {
        Ok(rewritten) => {
            let mut updated = tool_input.clone();
            // the part a chained wrapper must keep: unquoted, and unique per grant (its shell quoting may change the rest)
            let keep = rewritten
                .rfind("run --grant ")
                .and_then(|i| rewritten.get(i..))
                .unwrap_or(&rewritten)
                .to_owned();
            updated.set("command", Value::Str(rewritten));
            Own::Rewrite(updated, keep)
        }
        Err(e) => Own::Deny(deny(&e.to_string())),
    }
}

/// What a chained hook returned.
pub(super) struct Ran {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// The result of the whole chain.
#[derive(Debug, PartialEq, Eq)]
enum Out {
    /// Print this JSON (or nothing), exit 0.
    Json(Option<Value>),
    /// Exit 2 with this stderr: a chained hook blocked the call.
    Block(String),
}

fn rank(d: &str) -> u8 {
    match d {
        "deny" => 3,
        "ask" => 2,
        "allow" => 1,
        _ => 0,
    }
}

/// Compose keygent's step with the chained hooks, in order (`run` executes one hook on one payload).
fn compose(
    input: &Value,
    own: Own,
    chain: &[Value],
    run: &mut dyn FnMut(&Value, &str) -> Option<Ran>,
) -> Out {
    let (mut tool_input, keep) = match own {
        Own::Deny(d) => return Out::Json(Some(d)),
        Own::Rewrite(ti, cmd) => (Some(ti), Some(cmd)),
        Own::Pass => (None, None),
    };
    let mut decision: Option<(String, Option<Value>)> = None;
    let mut context: Vec<String> = Vec::new();
    let mut extra: Vec<(String, Value)> = Vec::new();
    for spec in chain {
        let mut payload = input.clone();
        if let Some(ti) = &tool_input {
            payload.set("tool_input", ti.clone());
        }
        let block_on_failure = spec.get("onFailure").and_then(Value::as_str) == Some("block");
        let Some(ran) = run(spec, &payload.compact()) else {
            if block_on_failure {
                return Out::Block(
                    "keygent: a chained hook failed to run — run 'keygent integrate claude' again"
                        .into(),
                );
            }
            continue;
        };
        match ran.code {
            Some(0) => {}
            Some(2) => return Out::Block(String::from_utf8_lossy(&ran.stderr).into_owned()),
            _ if block_on_failure => {
                return Out::Block(String::from_utf8_lossy(&ran.stderr).into_owned());
            }
            _ => continue,
        }
        let text = String::from_utf8_lossy(&ran.stdout);
        if text.trim().is_empty() {
            continue;
        }
        let Some(v) = json::parse(text.trim().as_bytes()) else {
            continue; // plain-text stdout from a hook that exits 0 is context-free noise for PreToolUse
        };
        if let Value::Obj(m) = &v {
            for (k, x) in m {
                // only Claude Code's documented common fields: undocumented ones (lean-ctx's `modifiedArgs`,
                // `updated_input`) can carry a command, and must not bring back a rewrite keygent refused
                if COMMON_FIELDS.contains(&k.as_str()) {
                    extra.retain(|(e, _)| e != k);
                    extra.push((k.clone(), x.clone()));
                }
            }
        }
        let Some(hso) = v.get("hookSpecificOutput") else {
            continue;
        };
        if let Some(d) = hso.get("permissionDecision").and_then(Value::as_str)
            && decision.as_ref().is_none_or(|(cur, _)| rank(d) > rank(cur))
        {
            decision = Some((d.to_owned(), hso.get("permissionDecisionReason").cloned()));
            if d == "deny" {
                return Out::Json(Some(Value::Obj(vec![(
                    "hookSpecificOutput".into(),
                    hso.clone(),
                )])));
            }
        }
        if let Some(c) = hso.get("additionalContext").and_then(Value::as_str) {
            context.push(c.to_owned());
        }
        if let Some(ui) = hso.get("updatedInput") {
            let cmd = ui
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            // keygent goes first: a chained hook may wrap keygent's command, never drop it
            if keep.as_deref().is_none_or(|k| cmd.contains(k)) {
                tool_input = Some(ui.clone());
            }
        }
    }
    let original = input.get("tool_input");
    let changed = tool_input.as_ref().is_some_and(|t| Some(t) != original);
    if !changed && decision.is_none() && context.is_empty() && extra.is_empty() {
        return Out::Json(None);
    }
    let mut hso = vec![("hookEventName".into(), Value::str("PreToolUse"))];
    if let Some((d, reason)) = decision {
        hso.push(("permissionDecision".into(), Value::Str(d)));
        if let Some(r) = reason {
            hso.push(("permissionDecisionReason".into(), r));
        }
    }
    if changed && let Some(t) = tool_input {
        hso.push(("updatedInput".into(), t));
    }
    if !context.is_empty() {
        hso.push(("additionalContext".into(), Value::Str(context.join("\n"))));
    }
    let mut top = vec![("hookSpecificOutput".to_owned(), Value::Obj(hso))];
    top.extend(extra);
    Out::Json(Some(Value::Obj(top)))
}

/// Run one chained command hook (`{type,command,args?,timeout?,…}` as in settings.json) with `payload` on stdin:
/// exec form when it has `args`, else `sh -c` like Claude Code. `None` = it could not be started or timed out.
fn run_spec(hook: &Value, payload: &str) -> Option<Ran> {
    let command = hook.get("command").and_then(Value::as_str)?;
    let mut c = match hook.get("args") {
        Some(Value::Arr(args)) => {
            let mut c = Command::new(command);
            for a in args {
                c.arg(a.as_str()?);
            }
            c
        }
        _ => {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(command);
            c
        }
    };
    let secs = match hook.get("timeout") {
        Some(Value::Num(n)) => n.parse::<u64>().ok().unwrap_or(CHAIN_TIMEOUT_DEFAULT),
        _ => CHAIN_TIMEOUT_DEFAULT,
    }
    .min(CHAIN_TIMEOUT_MAX);
    // its own process group, so a timeout kills what it started too (a grandchild would hold the pipes open)
    let mut child = c
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let input = payload.as_bytes().to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out = child.stdout.take()?;
    let mut err = child.stderr.take()?;
    let ro = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out
            .by_ref()
            .take(u64::try_from(json::MAX_INPUT).unwrap_or(u64::MAX))
            .read_to_end(&mut b);
        b
    });
    let re = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.by_ref().take(64 * 1024).read_to_end(&mut b);
        b
    });
    let deadline = Instant::now().checked_add(Duration::from_secs(secs))?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                ipc::signal_group(i32::try_from(child.id()).unwrap_or(0), libc::SIGKILL);
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let _ = writer.join();
    let stdout = ro.join().unwrap_or_default();
    let stderr = re.join().unwrap_or_default();
    let status = status?;
    Some(Ran {
        code: status.code(),
        stdout,
        stderr,
    })
}

pub fn pre(chain: &[String]) -> Result<()> {
    // each `--chain` is `{"at":<index>,"group":<settings.json group>}` written by `integrate claude`
    let mut hooks = Vec::new();
    for s in chain {
        let group = json::parse(s.as_bytes()).and_then(|c| c.get("group").cloned());
        match group.as_ref().and_then(|g| g.get("hooks")) {
            Some(Value::Arr(hs)) => hooks.extend(hs.iter().cloned()),
            _ => return Err(Error::Usage("keygent hook pre [--chain '<hook json>']…")),
        }
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .take(
            u64::try_from(json::MAX_INPUT)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut buf)?;
    let Some(input) = json::parse(&buf) else {
        let out = deny("keygent: unreadable hook input — run 'keygent doctor'");
        let _ = writeln!(std::io::stdout(), "{}", out.compact());
        return Ok(());
    };
    let launcher = std::env::current_exe().map_err(|_| Error::Internal(160))?;
    let launcher = launcher.to_str().ok_or(Error::Internal(161))?.to_owned();
    let own = own_step(&input, |command, cwd| {
        let d = platform::dirs()?;
        let (id, _state) = create_grant(&d, command, cwd, None, None)?;
        Ok(format!("{} run --grant {}", sh_quote(&launcher), hex(&id)))
    });
    match compose(&input, own, &hooks, &mut run_spec) {
        Out::Json(Some(v)) => {
            let _ = writeln!(std::io::stdout(), "{}", v.compact());
            Ok(())
        }
        Out::Json(None) => Ok(()),
        Out::Block(msg) => {
            let _ = write!(std::io::stderr(), "{msg}");
            Err(Error::Exit(2))
        }
    }
}

#[cfg(test)]
#[path = "hook_tests.rs"]
mod tests;
