//! Linux specifics: locations (passwd home, XDG env ignored), network-filesystem detection (PLATFORMS.md).
#![allow(unsafe_code)]

use super::Dirs;
use crate::error::{Error, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) fn dirs(home: &Path) -> Dirs {
    Dirs {
        data: home.join(".local").join("share").join("keygent"),
        config: home.join(".config").join("keygent"),
        state: home.join(".local").join("state").join("keygent"),
    }
}

/// statfs magic numbers of network and user-space filesystems (linux/magic.h).
const NETWORK_MAGIC: &[i64] = &[
    0x6969,      // NFS
    0x517B,      // SMB
    0xFF53_4D42, // CIFS
    0xFE53_4D42, // SMB2
    0x6573_5546, // FUSE (sshfs, rclone, …)
    0x0102_1997, // 9P (WSL /mnt, virtfs)
    0x7375_7245, // CODA
    0x5346_414F, // AFS
    0x0BD0_0BD0, // Lustre
    0x4750_4653, // GPFS
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
    #[allow(clippy::unnecessary_cast, clippy::cast_lossless)]
    let t = s.f_type as i64;
    Ok(NETWORK_MAGIC.contains(&t))
}
