//! The FFI entries of the mul, bitwise, shift-left and shift-right trace builders that read the
//! execution history, defined by the forwarders in `gpu-api/cuda/history/bitwise_mul_shift.cuh`.
//! `args` points at the host's copy of the launch arguments, `history.cuh`'s `HistoryArgs`;
//! `layout` is the `HISTORY_LAYOUT` it was built for.

use crate::Error;
use cudart_sys::*;
use std::ffi::c_void;

unsafe extern "C" {
    pub fn cuda_mul_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_bitwise_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_sll_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_sr_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;
}
