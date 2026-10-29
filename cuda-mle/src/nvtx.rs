//! NVTX ranges, for reading a phase off an nsys timeline.
//!
//! Kernel summaries (`nsys stats --report cuda_gpu_kern_sum`) have no time axis: they answer "did
//! this kernel get faster" but not "when did this run, and against what". A named range puts a
//! host-side phase on the timeline so its kernels can be told apart from everything else's.

use std::ffi::CString;

#[link(name = "nvToolsExt")]
extern "C" {
    fn nvtxRangePushA(message: *const std::os::raw::c_char) -> std::os::raw::c_int;
    fn nvtxRangePop() -> std::os::raw::c_int;
}

/// An open NVTX range; pops on drop. Held by value at the site being measured, so the range's extent
/// is the lexical scope.
pub struct Range {
    _private: (),
}

impl Drop for Range {
    fn drop(&mut self) {
        // SAFETY: pairs with the push in `range`. NVTX push/pop is per-thread, and `Range` is neither
        // `Send` nor `Sync` (the `()` field keeps it so), so the pop cannot happen on another thread.
        unsafe {
            nvtxRangePop();
        }
    }
}

/// Push a named range. Returns a guard; the range closes when it drops.
///
/// A `name` containing an interior NUL is dropped rather than truncated — this is instrumentation,
/// and silently mislabelling a range is worse than not labelling it.
pub fn range(name: &str) -> Option<Range> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` outlives the call; NVTX copies the string.
    unsafe {
        nvtxRangePushA(c.as_ptr());
    }
    Some(Range { _private: () })
}
