//! Command-line front end (SPEC §5.1): argument parsing, dispatch, and the one-line `keygent:` error contract
//! (ERRORS.md). Hand-rolled parser (DEPENDENCIES: no `clap`); unknown flags are usage errors, never ignored.

#[cfg(unix)]
mod client;
mod cmds;
mod console;
mod dotenv;
#[cfg(unix)]
mod grants;
mod recovery;
#[cfg(unix)]
mod session;

use crate::error::{Error, Result};
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "\
keygent — let AI coding agents use secrets without seeing them

Session:  unseal [--ttl 8h] · seal · status · ls
Run:      run [--max-runtime 30m] -- '<command with {{keygent:<handle>}}>' · run --grant <id>
Approve:  pending · approve [<id>] [--remember] · deny [<id> | --all]
Audit:    audit [--since 1h] [--verify]
Vault:    init [--own-passphrase] · passwd [--own-passphrase] · rekey · recover [--own-passphrase]
          verify · backup <file> · restore <file> [--new-machine] [--own-passphrase] · status
Secrets:  add <handle> [--env NAME] [--description TEXT] [--multiline | --from-file PATH [--delete]]
          rotate <handle> [--undo | --multiline | --from-file PATH [--delete]]
          rm <handle> · rename <old> <new> · ls · reveal <handle>
          edit <handle> [--env NAME] [--description TEXT] [--mode allow|confirm|approve|deny]
                        [--binding env|file] [--argv deny|allow]
          edit --settings [--ttl-max SECS] [--idle SECS] [--run-max-minutes N] [--remember on|off]
                          [--default-mode MODE]
          import <.env file> [--overwrite] [--delete]
Other:    version · help
";

/// Parsed arguments: positionals plus flags declared by the command (flag → optional value).
pub struct Args {
    pub pos: Vec<String>,
    flags: Vec<(&'static str, Option<String>)>,
}

impl Args {
    /// `spec`: `("--name", takes_value)`. Unknown flags, repeated flags and missing values are usage errors.
    fn parse(raw: &[String], spec: &[(&'static str, bool)], usage: &'static str) -> Result<Args> {
        let mut pos = Vec::new();
        let mut flags: Vec<(&'static str, Option<String>)> = Vec::new();
        let mut it = raw.iter();
        let mut only_pos = false;
        while let Some(a) = it.next() {
            if only_pos || !a.starts_with("--") {
                pos.push(a.clone());
                continue;
            }
            if a == "--" {
                only_pos = true;
                continue;
            }
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (a.as_str(), None),
            };
            let (key, takes) = spec
                .iter()
                .find(|(n, _)| *n == name)
                .copied()
                .ok_or(Error::Usage(usage))?;
            if flags.iter().any(|(k, _)| *k == key) {
                return Err(Error::Usage(usage));
            }
            let val = match (takes, inline) {
                (true, Some(v)) => Some(v),
                (true, None) => Some(it.next().ok_or(Error::Usage(usage))?.clone()),
                (false, None) => None,
                (false, Some(_)) => return Err(Error::Usage(usage)),
            };
            flags.push((key, val));
        }
        Ok(Args { pos, flags })
    }

    pub fn has(&self, f: &str) -> bool {
        self.flags.iter().any(|(k, _)| *k == f)
    }

    pub fn value(&self, f: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| *k == f)
            .and_then(|(_, v)| v.as_deref())
    }
}

fn run(argv: &[String]) -> Result<()> {
    let (cmd, rest) = argv
        .split_first()
        .ok_or(Error::Usage("keygent <command> — see 'keygent help'"))?;
    let rest = rest.to_vec();
    match cmd.as_str() {
        "help" | "--help" | "-h" => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            Ok(())
        }
        "version" | "--version" | "-V" => {
            let _ = writeln!(std::io::stdout(), "{}", build_id());
            Ok(())
        }
        #[cfg(unix)]
        "status" => session::status(Args::parse(&rest, &[], "keygent status")?),
        #[cfg(unix)]
        "unseal" => session::unseal(Args::parse(
            &rest,
            &[("--ttl", true), ("--log", true)],
            "keygent unseal [--ttl 8h] [--log info|debug]",
        )?),
        #[cfg(unix)]
        "run" => grants::run(Args::parse(
            &rest,
            &[
                ("--grant", true),
                ("--max-runtime", true),
                ("--dialect", true),
            ],
            "keygent run [--max-runtime 30m] -- '<command>' | run --grant <id>",
        )?),
        #[cfg(unix)]
        "audit" => session::audit(Args::parse(
            &rest,
            &[("--since", true), ("--verify", false)],
            "keygent audit [--since 1h] [--verify]",
        )?),
        #[cfg(unix)]
        "pending" => grants::pending(Args::parse(&rest, &[], "keygent pending")?),
        #[cfg(unix)]
        "approve" => grants::approve(Args::parse(
            &rest,
            &[("--remember", false)],
            "keygent approve [<id>] [--remember]",
        )?),
        #[cfg(unix)]
        "deny" => grants::deny(Args::parse(
            &rest,
            &[("--all", false)],
            "keygent deny [<id> | --all]",
        )?),
        #[cfg(unix)]
        "seal" => session::seal(Args::parse(&rest, &[], "keygent seal")?),
        #[cfg(all(unix, feature = "test-profile"))]
        "__redact" => session::test_redact(),
        #[cfg(unix)]
        "broker" => Err(Error::Usage(
            "keygent broker is started by 'keygent unseal'",
        )),
        "init" => cmds::init(Args::parse(
            &rest,
            &[("--own-passphrase", false)],
            "keygent init [--own-passphrase]",
        )?),
        "passwd" => cmds::passwd(Args::parse(
            &rest,
            &[("--own-passphrase", false)],
            "keygent passwd [--own-passphrase]",
        )?),
        "rekey" => cmds::rekey(Args::parse(&rest, &[], "keygent rekey")?),
        "recover" => cmds::recover(Args::parse(
            &rest,
            &[("--own-passphrase", false)],
            "keygent recover [--own-passphrase]",
        )?),
        "verify" => cmds::verify(Args::parse(&rest, &[], "keygent verify")?),
        "backup" => cmds::backup(Args::parse(&rest, &[], "keygent backup <file>")?),
        "restore" => cmds::restore(Args::parse(
            &rest,
            &[("--new-machine", false), ("--own-passphrase", false)],
            "keygent restore <file> [--new-machine] [--own-passphrase]",
        )?),
        "add" => cmds::add(Args::parse(
            &rest,
            &[
                ("--env", true),
                ("--description", true),
                ("--multiline", false),
                ("--from-file", true),
                ("--delete", false),
            ],
            "keygent add <handle> [--env NAME] [--description TEXT] [--multiline | --from-file PATH [--delete]]",
        )?),
        "rotate" => cmds::rotate(Args::parse(
            &rest,
            &[
                ("--undo", false),
                ("--multiline", false),
                ("--from-file", true),
                ("--delete", false),
            ],
            "keygent rotate <handle> [--undo | --multiline | --from-file PATH [--delete]]",
        )?),
        "rm" => cmds::rm(Args::parse(&rest, &[], "keygent rm <handle>")?),
        "rename" => cmds::rename(Args::parse(&rest, &[], "keygent rename <old> <new>")?),
        #[cfg(unix)]
        "ls" => session::ls(Args::parse(&rest, &[], "keygent ls")?),
        "reveal" => cmds::reveal(Args::parse(
            &rest,
            &[("--copy", false)],
            "keygent reveal <handle> [--copy]",
        )?),
        "edit" => cmds::edit(Args::parse(
            &rest,
            &[
                ("--env", true),
                ("--description", true),
                ("--mode", true),
                ("--binding", true),
                ("--argv", true),
                ("--settings", false),
                ("--ttl-max", true),
                ("--idle", true),
                ("--run-max-minutes", true),
                ("--remember", true),
                ("--default-mode", true),
            ],
            "keygent edit <handle> [--mode …] | edit --settings […] — see 'keygent help'",
        )?),
        "import" => cmds::import(Args::parse(
            &rest,
            &[("--overwrite", false), ("--delete", false)],
            "keygent import <.env file> [--overwrite] [--delete]",
        )?),
        _ => Err(Error::Usage("keygent <command> — see 'keygent help'")),
    }
}

/// Build id = semver + target triple (+ git commit when provided at build time) (SPEC §5.3).
pub fn build_id() -> String {
    let commit = option_env!("KEYGENT_GIT_COMMIT").unwrap_or("unknown");
    format!(
        "keygent {} ({commit}, {}-{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

pub fn main() -> ExitCode {
    // internal: `keygent broker` reads its handoff from the inherited pipe (started only by `unseal`)
    #[cfg(unix)]
    if std::env::args_os().nth(1).is_some_and(|a| a == "broker") && std::env::args_os().len() == 2 {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return crate::broker::main();
        }
    }
    let mut argv = Vec::new();
    for a in std::env::args_os().skip(1) {
        match a.into_string() {
            Ok(s) => argv.push(s),
            Err(_) => return fail(&Error::Usage("arguments must be UTF-8")),
        }
    }
    match run(&argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

fn fail(e: &Error) -> ExitCode {
    if let Error::Exit(code) = e {
        return ExitCode::from(*code);
    }
    let _ = writeln!(std::io::stderr(), "{e}");
    ExitCode::from(e.exit_code())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn args_strict() {
        let spec = [("--env", true), ("--delete", false)];
        let a = Args::parse(&s(&["h", "--env", "X", "--delete"]), &spec, "u").unwrap();
        assert_eq!(a.pos, vec!["h"]);
        assert_eq!(a.value("--env"), Some("X"));
        assert!(a.has("--delete"));
        let a = Args::parse(&s(&["--env=Y", "--", "--not-a-flag"]), &spec, "u").unwrap();
        assert_eq!(a.value("--env"), Some("Y"));
        assert_eq!(a.pos, vec!["--not-a-flag"]);
        assert!(Args::parse(&s(&["--unknown"]), &spec, "u").is_err());
        assert!(Args::parse(&s(&["--env"]), &spec, "u").is_err());
        assert!(Args::parse(&s(&["--delete=1"]), &spec, "u").is_err());
        assert!(Args::parse(&s(&["--env", "a", "--env", "b"]), &spec, "u").is_err());
    }

    #[test]
    fn unknown_command_is_usage() {
        assert_eq!(run(&s(&["frobnicate"])).unwrap_err().exit_code(), 64);
        assert_eq!(run(&[]).unwrap_err().exit_code(), 64);
    }
}
