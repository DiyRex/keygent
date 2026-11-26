//! keygent — sealed secrets broker for AI coding agents.

use std::process::ExitCode;

/// What the placeholder binary on `main` says for every command, until the first phase is merged.
const PLACEHOLDER: &str = "keygent: pre-alpha placeholder build, no commands work yet — see docs/ROADMAP.md for the first release";

#[allow(
    clippy::print_stderr,
    reason = "the placeholder's only output is its one agent-facing line"
)]
fn main() -> ExitCode {
    eprintln!("{PLACEHOLDER}");
    ExitCode::from(64)
}

#[cfg(test)]
mod tests {
    use super::PLACEHOLDER;

    #[test]
    fn placeholder_line_follows_the_output_style() {
        assert!(PLACEHOLDER.starts_with("keygent: "));
        assert!(PLACEHOLDER.chars().count() <= 120);
        assert!(!PLACEHOLDER.contains('\n'));
    }
}
