//! OS primitives behind one `Platform` trait (SPEC §4.2, ADR 0006, PLATFORMS.md). This is the only module that may
//! use `unsafe`/FFI (`libc` on Unix, `windows-sys` on Windows), each block with a `// SAFETY:` comment.
//!
//! Invariants:
//! - Locations come from the OS (passwd home dir, known folders), **never** from `HOME`/`XDG_*`/`TMPDIR` at runtime.
//!   The single exception is `KEYGENT_TEST_ROOT`, compiled in only with the `test-profile` feature.
//! - Private dirs/files are created owner-only and verified (not a symlink, owned by us, no group/other bits).
//! - Writes that replace a file are atomic and durable (temp + full sync + rename + dir sync).
//! - This module never holds secret values: console helpers hand raw bytes to the caller's zeroizing buffer.

use crate::error::Result;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub mod alloc;
#[cfg(unix)]
pub mod arena;
#[cfg(unix)]
pub mod ipc;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::Os;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Os;

/// Per-user keygent locations (PLATFORMS §Locations).
#[derive(Debug, Clone)]
pub struct Dirs {
    pub data: PathBuf,
    /// `config/config.toml` and `global.toml` (FORMATS §4).
    #[expect(
        dead_code,
        reason = "config.toml and the global manifest are read from Phase 3 on"
    )]
    pub config: PathBuf,
    pub state: PathBuf,
    /// Broker runtime dir (socket, `broker.lock`): fixed per user, owner-only.
    pub run: PathBuf,
}

/// RAII guard that restores the terminal mode on drop.
pub trait TermGuard {}

pub trait Platform {
    /// The user's home dir from the OS account database.
    fn home_dir(&self) -> Result<PathBuf>;
    /// OS default locations, derived from `home_dir()` / known folders only.
    fn default_dirs(&self) -> Result<Dirs>;
    /// Create `dir` (owner-only) if missing, then verify it is a real dir, owned by us, without group/other access.
    fn ensure_private_dir(&self, dir: &Path) -> Result<()>;
    /// Open an existing file for reading without following symlinks; verify owner and mode. `None` if missing.
    fn open_private(&self, path: &Path) -> Result<Option<File>>;
    /// Create a new owner-only file (fails if it exists, never follows symlinks).
    fn create_private(&self, path: &Path) -> Result<File>;
    /// Open a user-supplied input file (`--from-file`, `import`): regular file, owned by us, no symlink.
    fn open_user_input(&self, path: &Path) -> Result<File>;
    /// Full durability sync of a file (F_FULLFSYNC on macOS).
    fn sync_file(&self, f: &File) -> Result<()>;
    /// Sync a directory entry after rename/unlink.
    fn sync_dir(&self, dir: &Path) -> Result<()>;
    /// True if `path` lives on a network or sync filesystem (NFS, SMB, FUSE, iCloud Drive, OneDrive, Dropbox).
    fn is_network_or_sync(&self, path: &Path) -> Result<bool>;
    /// The controlling terminal for prompts (`/dev/tty`, `CONIN$`). `None` if there is none.
    fn open_tty(&self) -> Option<File>;
    /// Disable echo (and line editing if `raw`) on `tty` until the guard drops.
    fn term_mode(&self, tty: &File, raw: bool) -> Result<Box<dyn TermGuard>>;
    /// Wait until `f` is readable or `timeout` passes. Returns true if readable.
    fn wait_readable(&self, f: &File, timeout: Duration) -> Result<bool>;
    /// Put `text` on the clipboard, marked concealed where the OS supports it (macOS
    /// `org.nspasteboard.ConcealedType`). Returns a token for `clipboard_clear_if_ours`. The text passes through
    /// this call only; nothing is kept. Any same-user process can read the clipboard (known T2 gap, SPEC §5.1).
    fn clipboard_put(&self, text: &str) -> Result<u64>;
    /// Clear the clipboard if it still holds what `clipboard_put` placed there (never clobbers a later copy).
    fn clipboard_clear_if_ours(&self, token: u64, text: &str) -> Result<()>;
}

/// The platform implementation for this build.
pub fn os() -> Os {
    Os
}

/// Resolved locations. With the `test-profile` feature, `KEYGENT_TEST_ROOT` (an absolute, existing dir) redirects
/// everything under that root (tests/leak/README.md). Release builds have no override at all.
pub fn dirs() -> Result<Dirs> {
    #[cfg(feature = "test-profile")]
    if let Some(root) = std::env::var_os("KEYGENT_TEST_ROOT") {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err(crate::error::Error::UnsafePath("test root"));
        }
        return Ok(Dirs {
            data: root.join("data"),
            config: root.join("config"),
            state: root.join("state"),
            run: root.join("run"),
        });
    }
    os().default_dirs()
}

/// True when the test console (stdin/stderr instead of the terminal) is active. Only with `test-profile`;
/// `KEYGENT_TEST_USE_TTY` keeps the isolated root but exercises the real terminal path (pty smoke test).
pub fn test_console() -> bool {
    #[cfg(feature = "test-profile")]
    {
        std::env::var_os("KEYGENT_TEST_ROOT").is_some()
            && std::env::var_os("KEYGENT_TEST_USE_TTY").is_none()
    }
    #[cfg(not(feature = "test-profile"))]
    {
        false
    }
}

/// Write `bytes` to `dir/name` atomically: owner-only temp file in the same dir, full sync, rename, dir sync.
/// On any failure the temp file is removed and the original stays intact (disk full → `Error::DiskFull`).
pub fn atomic_replace(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let os = os();
    let suffix: String = crate::crypto::random_hex::<8>()?;
    let tmp = dir.join(format!("{name}.{suffix}.tmp"));
    let res = (|| -> Result<()> {
        let mut f = os.create_private(&tmp)?;
        f.write_all(bytes)?;
        os.sync_file(&f)?;
        drop(f);
        std::fs::rename(&tmp, dir.join(name))?;
        os.sync_dir(dir)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Remove stale `*.tmp` files left by an interrupted write (SPEC §5.2).
pub fn sweep_tmp(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".tmp") && name.starts_with("vault.kgt.") {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Path segments that mark sync-client folders, checked on the canonical path (case-insensitive).
pub(crate) fn is_sync_folder(canonical: &Path) -> bool {
    let mut s = canonical.to_string_lossy().to_ascii_lowercase();
    s.push('/');
    [
        "/library/mobile documents/",
        "/library/cloudstorage/",
        "/dropbox/",
        "/onedrive",
        "/icloud drive/",
        "/google drive/",
    ]
    .iter()
    .any(|m| s.contains(m))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: a panic is the failure report")]
    use super::*;

    #[test]
    fn sync_folders_detected() {
        assert!(is_sync_folder(Path::new(
            "/Users/u/Library/Mobile Documents/com~apple~CloudDocs/x/"
        )));
        assert!(is_sync_folder(Path::new(
            "/Users/u/Library/CloudStorage/OneDrive-Personal/x"
        )));
        assert!(is_sync_folder(Path::new("/home/u/Dropbox/vault/")));
        assert!(!is_sync_folder(Path::new(
            "/Users/u/Library/Application Support/keygent"
        )));
    }
}
