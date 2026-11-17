//! macOS specifics: locations, F_FULLFSYNC, network-filesystem detection (PLATFORMS.md).
#![allow(
    unsafe_code,
    reason = "platform layer: the only FFI in the crate; every block carries a SAFETY comment"
)]

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
        run: super::ipc::runtime_dir(&base.join("state")),
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
//
// The Objective-C runtime and AppKit are loaded with dlopen only here. Linking them (or Foundation, which the objc2
// crate always links) costs ~5–7 MB RSS in every keygent process — over the broker's 5 MB idle budget and bad for
// hook latency. `objc_msgSend` is called through casts to the exact prototype of each selector (required on arm64).

use std::ffi::{c_char, c_void};

type Id = *mut c_void;
type Sel = *mut c_void;

const CONCEALED: &[u8] = b"org.nspasteboard.ConcealedType";
const PLAIN: &[u8] = b"public.utf8-plain-text";
const NS_UTF8_ENCODING: usize = 4;

struct Objc {
    get_class: unsafe extern "C" fn(*const c_char) -> Id,
    sel: unsafe extern "C" fn(*const c_char) -> Sel,
    msg: *const c_void,
    pool_push: unsafe extern "C" fn() -> *mut c_void,
    pool_pop: unsafe extern "C" fn(*mut c_void),
}

fn sym(h: *mut c_void, name: &CStr) -> Result<*mut c_void> {
    // SAFETY: valid handle from dlopen and a NUL-terminated symbol name.
    let p = unsafe { libc::dlsym(h, name.as_ptr()) };
    if p.is_null() {
        Err(Error::Unsupported("reveal --copy"))
    } else {
        Ok(p)
    }
}

fn objc() -> Result<Objc> {
    // SAFETY: dlopen of system libraries by absolute path; handles are intentionally kept for the process lifetime.
    let (rt, appkit) = unsafe {
        (
            libc::dlopen(c"/usr/lib/libobjc.A.dylib".as_ptr(), libc::RTLD_LAZY),
            libc::dlopen(
                c"/System/Library/Frameworks/AppKit.framework/AppKit".as_ptr(),
                libc::RTLD_LAZY,
            ),
        )
    };
    if rt.is_null() || appkit.is_null() {
        return Err(Error::Unsupported("reveal --copy"));
    }
    // SAFETY: each symbol is cast to its documented C prototype from <objc/runtime.h> / <objc/objc-internal.h>.
    unsafe {
        Ok(Objc {
            get_class: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*const c_char) -> Id>(
                sym(rt, c"objc_getClass")?,
            ),
            sel: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*const c_char) -> Sel>(
                sym(rt, c"sel_registerName")?,
            ),
            msg: sym(rt, c"objc_msgSend")?,
            pool_push: std::mem::transmute::<*mut c_void, unsafe extern "C" fn() -> *mut c_void>(
                sym(rt, c"objc_autoreleasePoolPush")?,
            ),
            pool_pop: std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*mut c_void)>(sym(
                rt,
                c"objc_autoreleasePoolPop",
            )?),
        })
    }
}

impl Objc {
    fn class(&self, name: &CStr) -> Result<Id> {
        // SAFETY: NUL-terminated class name.
        let c = unsafe { (self.get_class)(name.as_ptr()) };
        if c.is_null() {
            Err(Error::Unsupported("reveal --copy"))
        } else {
            Ok(c)
        }
    }
    fn sel(&self, name: &CStr) -> Sel {
        // SAFETY: NUL-terminated selector name; sel_registerName never returns null for a valid name.
        unsafe { (self.sel)(name.as_ptr()) }
    }
    /// `id f(id, SEL)`
    unsafe fn send0(&self, obj: Id, sel: &CStr) -> Id {
        // SAFETY: caller guarantees the selector takes no arguments and returns an object pointer.
        unsafe {
            std::mem::transmute::<*const c_void, unsafe extern "C" fn(Id, Sel) -> Id>(self.msg)(
                obj,
                self.sel(sel),
            )
        }
    }
    /// `NSInteger f(id, SEL)`
    unsafe fn send0_int(&self, obj: Id, sel: &CStr) -> isize {
        // SAFETY: caller guarantees the selector takes no arguments and returns NSInteger.
        unsafe {
            std::mem::transmute::<*const c_void, unsafe extern "C" fn(Id, Sel) -> isize>(self.msg)(
                obj,
                self.sel(sel),
            )
        }
    }

    /// An NSString from UTF-8 bytes (+1 retained; the caller releases it). Foundation's copy of the value is outside
    /// our control (documented T2 residual of `--copy`).
    unsafe fn nsstring(&self, bytes: &[u8]) -> Result<Id> {
        // SAFETY: +alloc on NSString, then -initWithBytes:length:encoding: (const void*, NSUInteger, NSUInteger) -> id.
        unsafe {
            let obj = self.send0(self.class(c"NSString")?, c"alloc");
            let f = std::mem::transmute::<
                *const c_void,
                unsafe extern "C" fn(Id, Sel, *const c_void, usize, usize) -> Id,
            >(self.msg);
            let s = f(
                obj,
                self.sel(c"initWithBytes:length:encoding:"),
                bytes.as_ptr().cast(),
                bytes.len(),
                NS_UTF8_ENCODING,
            );
            if s.is_null() {
                Err(Error::Unsupported("reveal --copy"))
            } else {
                Ok(s)
            }
        }
    }
}

/// NSPasteboard with the plain-text type plus `org.nspasteboard.ConcealedType`, which clipboard managers honour by
/// not recording the item. Token = the pasteboard `changeCount` after our write.
pub(super) fn clipboard_put(text: &str) -> Result<u64> {
    let o = objc()?;
    // SAFETY: documented NSArray/NSPasteboard selectors, each called through its exact prototype; objects created
    // with alloc/init are released, everything else is autoreleased into the pool we pop at the end.
    unsafe {
        let pool = (o.pool_push)();
        let r = (|| -> Result<isize> {
            let pb = o.send0(o.class(c"NSPasteboard")?, c"generalPasteboard");
            if pb.is_null() {
                return Err(Error::Unsupported("reveal --copy"));
            }
            let plain = o.nsstring(PLAIN)?;
            let concealed = o.nsstring(CONCEALED)?;
            let value = o.nsstring(text.as_bytes())?;
            let items: [Id; 2] = [plain, concealed];
            let arr = std::mem::transmute::<
                *const c_void,
                unsafe extern "C" fn(Id, Sel, *const Id, usize) -> Id,
            >(o.msg)(
                o.class(c"NSArray")?,
                o.sel(c"arrayWithObjects:count:"),
                items.as_ptr(),
                items.len(),
            );
            let declare = std::mem::transmute::<
                *const c_void,
                unsafe extern "C" fn(Id, Sel, Id, Id) -> isize,
            >(o.msg);
            let set = std::mem::transmute::<
                *const c_void,
                unsafe extern "C" fn(Id, Sel, Id, Id) -> u8,
            >(o.msg);
            let _ = o.send0_int(pb, c"clearContents");
            let _ = declare(pb, o.sel(c"declareTypes:owner:"), arr, std::ptr::null_mut());
            let a = set(pb, o.sel(c"setString:forType:"), value, plain) != 0;
            let b = set(pb, o.sel(c"setString:forType:"), value, concealed) != 0;
            for s in [plain, concealed, value] {
                let _ = o.send0(s, c"release");
            }
            if !(a && b) {
                let _ = o.send0_int(pb, c"clearContents");
                return Err(Error::Unsupported("reveal --copy"));
            }
            Ok(o.send0_int(pb, c"changeCount"))
        })();
        (o.pool_pop)(pool);
        u64::try_from(r?).map_err(|_| Error::Internal(70))
    }
}

pub(super) fn clipboard_clear_if_ours(token: u64, _text: &str) -> Result<()> {
    let o = objc()?;
    // SAFETY: -changeCount / -clearContents take no arguments and return NSInteger; generalPasteboard returns id.
    unsafe {
        let pool = (o.pool_push)();
        let pb = o.send0(o.class(c"NSPasteboard")?, c"generalPasteboard");
        if !pb.is_null() && u64::try_from(o.send0_int(pb, c"changeCount")).ok() == Some(token) {
            let _ = o.send0_int(pb, c"clearContents");
        }
        (o.pool_pop)(pool);
    }
    Ok(())
}
