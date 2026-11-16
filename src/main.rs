//! keygent — sealed secrets broker for AI coding agents. Argument parsing and dispatch only (SPEC §4.2).

#![forbid(clippy::dbg_macro)]

mod adapter;
#[cfg(unix)]
mod broker;
mod cli;
mod crypto;
mod error;
mod hook;
mod platform;
mod policy;
mod proto;
mod redact;
mod vault;

use std::process::ExitCode;

/// Freed heap is wiped before reuse (SPEC §5.4).
#[global_allocator]
static ALLOC: platform::alloc::ZeroOnFree = platform::alloc::ZeroOnFree;

fn main() -> ExitCode {
    // panic = "abort" in release; the hook prints a fixed string only, never the payload (BUILD_PROMPT §5).
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            format!("keygent: internal error at {loc} — run 'keygent doctor'\n").as_bytes(),
        );
    }));
    cli::main()
}
