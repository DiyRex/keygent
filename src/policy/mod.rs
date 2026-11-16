//! Tokenizers, placeholder rewrite, executable resolution and render_for_approval() — never touches secret types
//! (SPEC §4.2, §5.5.2, §5.7, §6).

pub mod render;
#[cfg(unix)]
pub mod resolve;
pub mod rewrite;
pub mod tokenize;
