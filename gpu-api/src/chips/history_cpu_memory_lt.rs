//! The FFI entries of the CPU, program, memory read/write and less-than trace builders that read
//! the execution history, defined by the forwarders in `gpu-api/cuda/history/cpu_memory_lt.cuh`.
//! `args` points at the host's copy of the launch arguments, `history.cuh`'s `HistoryArgs`;
//! `layout` is the `HISTORY_LAYOUT` it was built for. The CPU chip's rows take one call per slice,
//! `slice` of `slices` cut every `slice_steps` steps, and its padding one more.
//! `cuda_history_spin` holds `stream` for `nanoseconds`, for the tests that delay one producer of
//! an ordering edge.

use crate::Error;
use cudart_sys::*;
use std::ffi::c_void;

unsafe extern "C" {
    pub fn cuda_cpu_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        slice: u32,
        slices: u32,
        slice_steps: usize,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_cpu_pad_trace_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_riscv_program_generate_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        instructions: usize,
        d_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_memory_read_write_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_history_spin(nanoseconds: u64, stream: cudaStream_t) -> Error;

    pub fn cuda_lt_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;
}
