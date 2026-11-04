//! The FFI entries of the ecall and RISC-V syscall trace builders that read the execution history,
//! defined by the forwarders in `gpu-api/cuda/history/ecall_syscall.cuh`. `args` points at the
//! host's copy of the launch arguments, `history.cuh`'s `HistoryArgs`; `layout` is the
//! `HISTORY_LAYOUT` it was built for. The syscall entry writes one global event per row into the
//! `global_slots` slots the host reserved from `global_events_start_index` on, and fails the chunk
//! through the error word when the fill holds another number of syscall rows.

use crate::Error;
use cudart_sys::*;
use std::ffi::c_void;

unsafe extern "C" {
    pub fn cuda_ecall_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    /// `d_global_events` may be null only when `global_slots` is 0.
    pub fn cuda_syscall_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        d_global_events: *mut c_void,
        global_events_start_index: usize,
        global_slots: usize,
        stream: cudaStream_t,
    ) -> Error;
}
