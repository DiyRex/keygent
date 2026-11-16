//! Locked arena for secret bytes (SPEC §5.4): one `mmap`ed region, `mlock`ed (never swapped), excluded from core
//! dumps where the OS supports it. Secrets are copied in; blocks are wiped on free. If the region can't be locked,
//! `init` fails and the broker refuses to start.
//!
//! First-fit free list with 16-byte granularity; the arena is sized at unseal from the vault's value sizes.
#![allow(unsafe_code)]

use crate::error::{Error, Result};
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

const ALIGN: usize = 16;

struct Arena {
    base: NonNull<u8>,
    /// Free blocks as (offset, len), sorted by offset, coalesced.
    free: Vec<(usize, usize)>,
}

// SAFETY: the region is only accessed through `LockedBuf`s, each owning a disjoint block; the free list is behind
// the mutex.
unsafe impl Send for Arena {}

static ARENA: OnceLock<Mutex<Arena>> = OnceLock::new();

fn round_up(n: usize, to: usize) -> Option<usize> {
    n.checked_add(to.checked_sub(1)?)?
        .checked_div(to)?
        .checked_mul(to)
}

/// Map and lock `bytes` (rounded to pages). Idempotent: a second call fails.
pub fn init(bytes: usize) -> Result<()> {
    // SAFETY: sysconf has no preconditions.
    let page = usize::try_from(unsafe { libc_page() })
        .unwrap_or(4096)
        .max(4096);
    let size = round_up(bytes.max(page), page).ok_or(Error::TooLarge("arena"))?;
    // SAFETY: anonymous private mapping, no fd, checked result.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return Err(Error::Internal(80));
    }
    // SAFETY: `p` is a fresh mapping of `size` bytes.
    if unsafe { libc::mlock(p, size) } != 0 {
        // SAFETY: unmapping the mapping we just created.
        unsafe { libc::munmap(p, size) };
        return Err(Error::Unsupported(
            "locking secret memory (raise RLIMIT_MEMLOCK)",
        ));
    }
    #[cfg(target_os = "linux")]
    // SAFETY: advisory flag on our own mapping.
    unsafe {
        libc::madvise(p, size, libc::MADV_DONTDUMP);
    }
    let base = NonNull::new(p.cast::<u8>()).ok_or(Error::Internal(81))?;
    ARENA
        .set(Mutex::new(Arena {
            base,
            free: vec![(0, size)],
        }))
        .map_err(|_| Error::Internal(82))
}

unsafe fn libc_page() -> libc::c_long {
    // SAFETY: sysconf has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
}

/// A block of locked memory holding secret bytes. Wiped and returned to the arena on drop. Never `Clone`/`Debug`.
pub struct LockedBuf {
    ptr: NonNull<u8>,
    len: usize,
    off: usize,
    cap: usize,
}

// SAFETY: a LockedBuf exclusively owns its block.
unsafe impl Send for LockedBuf {}
// SAFETY: shared access is read-only through `as_slice`.
unsafe impl Sync for LockedBuf {}

impl LockedBuf {
    /// Copy `data` into the arena. `None` if there is no arena; `Err` if it is full (fail closed).
    pub fn copy_from(data: &[u8]) -> Option<Result<LockedBuf>> {
        let arena = ARENA.get()?;
        Some((|| {
            let cap = round_up(data.len().max(1), ALIGN).ok_or(Error::TooLarge("secret"))?;
            let mut a = arena.lock().map_err(|_| Error::Internal(83))?;
            let i = a
                .free
                .iter()
                .position(|&(_, l)| l >= cap)
                .ok_or(Error::TooLarge("locked memory"))?;
            let (off, l) = *a.free.get(i).ok_or(Error::Internal(84))?;
            if l == cap {
                a.free.remove(i);
            } else if let Some(slot) = a.free.get_mut(i) {
                *slot = (off.saturating_add(cap), l.saturating_sub(cap));
            }
            // SAFETY: off + cap <= size, inside the mapping.
            let ptr = unsafe { NonNull::new_unchecked(a.base.as_ptr().add(off)) };
            drop(a);
            // SAFETY: the block [off, off+cap) is exclusively ours and data.len() <= cap.
            unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr(), data.len()) };
            Ok(LockedBuf {
                ptr,
                len: data.len(),
                off,
                cap,
            })
        })())
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for len initialized bytes for our lifetime.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        // SAFETY: we own [ptr, ptr+cap).
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap) }.zeroize();
        if let Some(arena) = ARENA.get()
            && let Ok(mut a) = arena.lock()
        {
            let pos = a.free.partition_point(|&(o, _)| o < self.off);
            a.free.insert(pos, (self.off, self.cap));
            // coalesce neighbours
            let mut merged: Vec<(usize, usize)> = Vec::with_capacity(a.free.len());
            for &(o, l) in &a.free {
                match merged.last_mut() {
                    Some((po, pl)) if po.saturating_add(*pl) == o => *pl = pl.saturating_add(l),
                    _ => merged.push((o, l)),
                }
            }
            a.free = merged;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn locked_blocks_roundtrip_and_free() {
        // the arena is process-global; other tests may share it, so only check what this test owns
        let _ = init(256 * 1024);
        let a = LockedBuf::copy_from(b"KEYGENT_CANARY_arena_one")
            .unwrap()
            .unwrap();
        let b = LockedBuf::copy_from(&[7u8; 1000]).unwrap().unwrap();
        assert_eq!(a.as_slice(), b"KEYGENT_CANARY_arena_one");
        assert_eq!(b.as_slice(), &[7u8; 1000][..]);
        drop(a);
        let c = LockedBuf::copy_from(b"x").unwrap().unwrap();
        assert_eq!(c.as_slice(), b"x");
        assert!(
            LockedBuf::copy_from(&vec![0u8; 64 * 1024 * 1024])
                .unwrap()
                .is_err(),
            "a full arena fails closed"
        );
    }
}
