//! Unix implementation shared by Linux and macOS (PLATFORMS §Primitives).
#![allow(unsafe_code)]

use super::{Dirs, Platform, TermGuard};
use crate::error::{Error, Result};
use std::ffi::CStr;
use std::fs::{DirBuilder, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct Os;

fn uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// Owner = us, no group/other bits, not a symlink (lstat semantics: `meta` must come from symlink_metadata or an
/// O_NOFOLLOW handle).
fn check_owner_mode(meta: &std::fs::Metadata, what: &'static str) -> Result<()> {
    if meta.file_type().is_symlink() || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
        return Err(Error::UnsafePath(what));
    }
    Ok(())
}

/// Home dir from the passwd database (`getpwuid_r`), never `$HOME` (SPEC §5.4).
fn passwd_home() -> Option<PathBuf> {
    let mut buf = vec![0u8; 16 * 1024];
    // SAFETY: passwd is plain-old-data; zeroed is a valid initial value.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the given lengths; `out` is set to &pw or null by the call.
    let rc =
        unsafe { libc::getpwuid_r(uid(), &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: on success pw_dir points to a NUL-terminated string inside `buf`, which is still alive.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    let p = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    p.is_absolute().then_some(p)
}

struct Termios {
    fd: i32,
    saved: libc::termios,
}

impl TermGuard for Termios {}

impl Drop for Termios {
    fn drop(&mut self) {
        // SAFETY: fd is the tty we read the settings from; saved is a valid termios.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved);
        }
    }
}

impl Platform for Os {
    fn home_dir(&self) -> Result<PathBuf> {
        if let Some(h) = passwd_home() {
            return Ok(h);
        }
        // SPEC §5.4: $HOME only if owned by us and not group/world-writable (doctor notes the fallback).
        let h = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(Error::UnsafePath("home dir"))?;
        let m = std::fs::symlink_metadata(&h)?;
        if !h.is_absolute() || !m.is_dir() || m.uid() != uid() || m.mode() & 0o022 != 0 {
            return Err(Error::UnsafePath("home dir"));
        }
        Ok(h)
    }

    fn default_dirs(&self) -> Result<Dirs> {
        let home = self.home_dir()?;
        #[cfg(target_os = "macos")]
        return Ok(super::macos::dirs(&home));
        #[cfg(target_os = "linux")]
        return Ok(super::linux::dirs(&home));
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = home;
            Err(Error::Unsupported("this OS"))
        }
    }

    fn ensure_private_dir(&self, dir: &Path) -> Result<()> {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let m = std::fs::symlink_metadata(dir)?;
        if !m.is_dir() {
            return Err(Error::UnsafePath("keygent dir"));
        }
        check_owner_mode(&m, "keygent dir")
    }

    fn open_private(&self, path: &Path) -> Result<Option<File>> {
        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => {
                let m = f.metadata()?;
                if !m.is_file() {
                    return Err(Error::UnsafePath("vault file"));
                }
                check_owner_mode(&m, "vault file")?;
                Ok(Some(f))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(Error::UnsafePath("vault file")),
            Err(e) => Err(e.into()),
        }
    }

    fn create_private(&self, path: &Path) -> Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(Error::from)
    }

    fn open_user_input(&self, path: &Path) -> Result<File> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Error::NotRegularFile)?;
        let m = f.metadata()?;
        if !m.is_file() || m.uid() != uid() {
            return Err(Error::NotRegularFile);
        }
        Ok(f)
    }

    fn sync_file(&self, f: &File) -> Result<()> {
        #[cfg(target_os = "macos")]
        return super::macos::full_fsync(f);
        #[cfg(not(target_os = "macos"))]
        f.sync_all().map_err(Error::from)
    }

    fn sync_dir(&self, dir: &Path) -> Result<()> {
        let d = File::open(dir)?;
        d.sync_all().map_err(Error::from)
    }

    fn is_network_or_sync(&self, path: &Path) -> Result<bool> {
        let canon = std::fs::canonicalize(path)?;
        if super::is_sync_folder(&canon) {
            return Ok(true);
        }
        #[cfg(target_os = "macos")]
        return super::macos::is_network_fs(&canon);
        #[cfg(target_os = "linux")]
        return super::linux::is_network_fs(&canon);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Ok(false)
    }

    fn open_tty(&self) -> Option<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
            .open("/dev/tty")
            .ok()
    }

    fn term_mode(&self, tty: &File, raw: bool) -> Result<Box<dyn TermGuard>> {
        let fd = tty.as_raw_fd();
        // SAFETY: termios is POD; tcgetattr fills it for a valid fd.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is an open tty for the lifetime of this call; t is a valid out-pointer.
        if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
            return Err(Error::NeedsAuth);
        }
        let saved = t;
        t.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if raw {
            t.c_lflag &= !libc::ICANON;
            t.c_cc[libc::VMIN] = 1;
            t.c_cc[libc::VTIME] = 0;
        }
        // SAFETY: valid fd and termios.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &t) } != 0 {
            return Err(Error::NeedsAuth);
        }
        Ok(Box::new(Termios { fd, saved }))
    }

    fn wait_readable(&self, f: &File, timeout: Duration) -> Result<bool> {
        let mut p = libc::pollfd {
            fd: f.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one valid pollfd for the duration of the call.
        let r = unsafe { libc::poll(&mut p, 1, ms) };
        if r < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(r > 0)
    }
}
