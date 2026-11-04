//! The FFI entries of the add, addw, sub, subw and div/rem trace builders that read the execution
//! history, defined by the forwarders in `gpu-api/cuda/history/add_sub_divrem.cuh`. `args`
//! points at the host's copy of the launch arguments, `history.cuh`'s `HistoryArgs`; `layout` is
//! the `HISTORY_LAYOUT` it was built for. Div/rem appends the ADD rows it derives to `d_derived`,
//! `capacity` events long, and writes how many it appended to `d_appended`, one `u32`; the add
//! entry reads the same `capacity` events after the add list's own rows.

use crate::Error;
use cudart_sys::*;
use std::ffi::c_void;

unsafe extern "C" {
    pub fn cuda_add_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        d_derived: *const c_void,
        capacity: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_addw_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_sub_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_subw_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_divrem_generate_extra_record_and_main_history(
        args: *const c_void,
        layout: u32,
        num_cols: usize,
        trace_size: usize,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        d_derived: *mut c_void,
        capacity: usize,
        d_appended: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;
}
