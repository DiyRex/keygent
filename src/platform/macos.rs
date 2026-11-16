//! macOS specifics: locations, F_FULLFSYNC, network-filesystem detection (PLATFORMS.md).
#![allow(unsafe_code)]

use super::Dirs;
use crate::error::{Error, Result};
use std::ffi::CStr;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) fn dirs(home: &Path) -> Dirs {
    let base = home
        .join("Library")
        .join("Application Support")
        .join("keygent");
    Dirs {
        config: base.join("config"),
        state: base.join("state"),
        data: base,
    }
}

/// `fsync` on macOS doesn't flush the drive cache; F_FULLFSYNC does (falls back to fsync if unsupported, e.g. some
/// network or FUSE filesystems — which we refuse anyway).
pub(super) fn full_fsync(f: &File) -> Result<()> {
    // SAFETY: fcntl(F_FULLFSYNC) on an open fd has no memory-safety preconditions.
    let r = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC) };
    if r == -1 {
        return f.sync_all().map_err(Error::from);
    }
    Ok(())
}

/// Filesystem type names that are network or user-space mounts.
const NETWORK_FS: &[&[u8]] = &[
    b"nfs", b"smbfs", b"afpfs", b"webdav", b"cifs", b"ftp", b"macfuse", b"osxfuse", b"fuse",
];

pub(super) fn is_network_fs(canon: &Path) -> Result<bool> {
    let c = std::ffi::CString::new(canon.as_os_str().as_bytes())
        .map_err(|_| Error::UnsafePath("path"))?;
    // SAFETY: statfs is POD; zeroed is valid and the call fills it.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid NUL-terminated path; s is a valid out-pointer.
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: f_fstypename is a NUL-terminated fixed array filled by statfs.
    let name = unsafe { CStr::from_ptr(s.f_fstypename.as_ptr()) }.to_bytes();
    let local = s.f_flags & (libc::MNT_LOCAL as u32) != 0;
    Ok(!local || NETWORK_FS.iter().any(|n| name.starts_with(n)))
}
