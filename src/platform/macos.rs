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

// ---------------------------------------------------------------- clipboard (reveal --copy)

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}

const CONCEALED: &str = "org.nspasteboard.ConcealedType";
const PLAIN: &str = "public.utf8-plain-text";

fn pasteboard() -> Result<objc2::rc::Retained<objc2::runtime::AnyObject>> {
    let cls = objc2::runtime::AnyClass::get(c"NSPasteboard")
        .ok_or(Error::Unsupported("reveal --copy"))?;
    // SAFETY: +[NSPasteboard generalPasteboard] takes no arguments and returns an NSPasteboard (or nil).
    let pb: Option<objc2::rc::Retained<objc2::runtime::AnyObject>> =
        unsafe { objc2::msg_send![cls, generalPasteboard] };
    pb.ok_or(Error::Unsupported("reveal --copy"))
}

/// NSPasteboard with the plain-text type plus `org.nspasteboard.ConcealedType`, which clipboard managers honour by
/// not recording the item. Token = the pasteboard `changeCount` after our write.
pub(super) fn clipboard_put(text: &str) -> Result<u64> {
    use objc2_foundation::{NSArray, NSString};
    let pb = pasteboard()?;
    let plain = NSString::from_str(PLAIN);
    let concealed = NSString::from_str(CONCEALED);
    let value = NSString::from_str(text);
    let types = NSArray::from_slice(&[&*plain, &*concealed]);
    let none: Option<&objc2::runtime::AnyObject> = None;
    // SAFETY: documented NSPasteboard selectors with matching argument and return types (NSInteger / BOOL).
    let count: isize = unsafe {
        let _: isize = objc2::msg_send![&*pb, clearContents];
        let _: isize = objc2::msg_send![&*pb, declareTypes: &*types, owner: none];
        let a: bool = objc2::msg_send![&*pb, setString: &*value, forType: &*plain];
        let b: bool = objc2::msg_send![&*pb, setString: &*value, forType: &*concealed];
        if !(a && b) {
            let _: isize = objc2::msg_send![&*pb, clearContents];
            return Err(Error::Unsupported("reveal --copy"));
        }
        objc2::msg_send![&*pb, changeCount]
    };
    u64::try_from(count).map_err(|_| Error::Internal(70))
}

pub(super) fn clipboard_clear_if_ours(token: u64, _text: &str) -> Result<()> {
    let pb = pasteboard()?;
    // SAFETY: -changeCount / -clearContents take no arguments and return NSInteger.
    unsafe {
        let now: isize = objc2::msg_send![&*pb, changeCount];
        if u64::try_from(now).ok() == Some(token) {
            let _: isize = objc2::msg_send![&*pb, clearContents];
        }
    }
    Ok(())
}
