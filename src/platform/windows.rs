//! Windows implementation — **deferred** (ADR 0010): no Windows host is available yet, so every primitive fails
//! closed with `Unsupported` instead of silently doing nothing (BUILD_PROMPT §5 "no silent no-op fallback").
//! Planned primitives: known-folder locations, protected owner-only DACLs, reparse-point refusal,
//! `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)`, `CONIN$` without echo (PLATFORMS.md).

use super::{Dirs, Platform, TermGuard};
use crate::error::{Error, Result};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Os;

const NA: Error = Error::Unsupported("Windows");

impl Platform for Os {
    fn home_dir(&self) -> Result<PathBuf> {
        Err(NA)
    }
    fn default_dirs(&self) -> Result<Dirs> {
        Err(NA)
    }
    fn ensure_private_dir(&self, _: &Path) -> Result<()> {
        Err(NA)
    }
    fn open_private(&self, _: &Path) -> Result<Option<File>> {
        Err(NA)
    }
    fn create_private(&self, _: &Path) -> Result<File> {
        Err(NA)
    }
    fn open_user_input(&self, _: &Path) -> Result<File> {
        Err(NA)
    }
    fn sync_file(&self, _: &File) -> Result<()> {
        Err(NA)
    }
    fn sync_dir(&self, _: &Path) -> Result<()> {
        Err(NA)
    }
    fn is_network_or_sync(&self, _: &Path) -> Result<bool> {
        Err(NA)
    }
    fn open_tty(&self) -> Option<File> {
        None
    }
    fn term_mode(&self, _: &File, _: bool) -> Result<Box<dyn TermGuard>> {
        Err(NA)
    }
    fn wait_readable(&self, _: &File, _: Duration) -> Result<bool> {
        Err(NA)
    }
    fn clipboard_put(&self, _: &str) -> Result<u64> {
        Err(NA)
    }
    fn clipboard_clear_if_ours(&self, _: u64, _: &str) -> Result<()> {
        Err(NA)
    }
}
