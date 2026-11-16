//! Linux specifics: locations (passwd home, XDG env ignored), network-filesystem detection (PLATFORMS.md).
#![allow(unsafe_code)]

use super::Dirs;
use crate::error::{Error, Result};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub(super) fn dirs(home: &Path) -> Dirs {
    let state = home.join(".local").join("state").join("keygent");
    Dirs {
        run: super::ipc::runtime_dir(&state),
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

// ---------------------------------------------------------------- clipboard (reveal --copy)

/// Fixed tool paths (never PATH): Wayland `wl-copy`/`wl-paste`, else X11 `xclip`. The value goes over stdin, never argv.
const WL_COPY: &str = "/usr/bin/wl-copy";
const WL_PASTE: &str = "/usr/bin/wl-paste";
const XCLIP: &str = "/usr/bin/xclip";

fn tool() -> Result<(
    &'static str,
    &'static [&'static str],
    &'static str,
    &'static [&'static str],
)> {
    if Path::new(WL_COPY).exists() && Path::new(WL_PASTE).exists() {
        return Ok((WL_COPY, &[], WL_PASTE, &["--no-newline"]));
    }
    if Path::new(XCLIP).exists() {
        return Ok((
            XCLIP,
            &["-selection", "clipboard"],
            XCLIP,
            &["-selection", "clipboard", "-o"],
        ));
    }
    Err(Error::Unsupported(
        "reveal --copy (install wl-clipboard or xclip)",
    ))
}

fn put(bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let (copy, args, _, _) = tool()?;
    let mut c = Command::new(copy)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut i) = c.stdin.take() {
        i.write_all(bytes)?;
    }
    if !c.wait()?.success() {
        return Err(Error::Unsupported("reveal --copy"));
    }
    Ok(())
}

pub(super) fn clipboard_put(text: &str) -> Result<u64> {
    put(text.as_bytes())?;
    Ok(0)
}

/// Read the clipboard back and clear it only if it still holds our value (constant-time compare).
pub(super) fn clipboard_clear_if_ours(_token: u64, text: &str) -> Result<()> {
    use std::process::{Command, Stdio};
    let (_, _, paste, pargs) = tool()?;
    let out = Command::new(paste)
        .args(pargs)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;
    let current = zeroize::Zeroizing::new(out.stdout);
    if crate::crypto::ct_eq(&current, text.as_bytes()) {
        put(b"")?;
    }
    Ok(())
}
