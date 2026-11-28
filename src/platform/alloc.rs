//! Zero-on-free global allocator (SPEC §5.4 "Everything else is freed through a zero-on-free allocator").
//! Every deallocation (and the old block of every reallocation) is wiped with volatile writes before it returns
//! to the system allocator, so freed heap never keeps stale plaintext for the next allocation to see.
#![allow(
    unsafe_code,
    reason = "platform layer: the only FFI in the crate; every block carries a SAFETY comment"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use zeroize::Zeroize;

pub struct ZeroOnFree;

// SAFETY: delegates every allocation to `System` with the same layout; dealloc only adds a wipe of exactly the
// `layout.size()` bytes the caller owned, before handing the block back.
unsafe impl GlobalAlloc for ZeroOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ptr.is_null() && layout.size() > 0 {
            // SAFETY: `ptr` was returned by `alloc` for `layout`, so it is valid for `layout.size()` writes and the
            // caller no longer uses it.
            unsafe { std::slice::from_raw_parts_mut(ptr, layout.size()) }.zeroize();
        }
        // SAFETY: same contract as the caller's.
        unsafe { System.dealloc(ptr, layout) }
    }
    // `realloc` uses the default (alloc new, copy, dealloc old), so the old block is wiped too.
}
