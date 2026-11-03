//! The device self-test of the history loaders, defined in the kernel library's
//! `tracegen/riscv/history_self_test.cu`: a dump's fill, program table and stream rows uploaded,
//! every stream rebuilt on the device and compared row by row with the dump's.

use crate::Error;
use std::ffi::c_void;

unsafe extern "C" {
    /// `rows` and `counts` hold, for each stream in the kernel library's `history_check` order,
    /// the host address and the row count of the dump's rows; `rebuilt`, `mismatched` and `first`
    /// receive as many values, and `error_word` the loaders' error bits. The kernels are launched
    /// for `expected`, a `FillIdentity`, or for the fill's own identity when it is null.
    /// Synchronous on the current device.
    pub fn cuda_history_self_test(
        layout: u32,
        fill: *const u8,
        fill_bytes: u64,
        program: *const c_void,
        program_rows: u64,
        pc_base: u64,
        program_key: u64,
        rows: *const *const c_void,
        counts: *const u64,
        bitmap: u32,
        expected: *const c_void,
        rebuilt: *mut u64,
        mismatched: *mut u64,
        first: *mut u64,
        error_word: *mut u32,
    ) -> Error;
}
