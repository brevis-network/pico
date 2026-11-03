//! The whole-fill checks of the execution history, defined by the forwarder in
//! `gpu-api/cuda/history/validate.cu`: the order of the exception table and of every chip list,
//! which no loader can check from the rows it reads.

use crate::Error;
use cudart_sys::*;
use std::ffi::c_void;

unsafe extern "C" {
    /// Launches on `stream` the checks of the fill `args` names, a host pointer to `history.cuh`'s
    /// `HistoryArgs` built for the `HISTORY_LAYOUT` `layout` names. A failed check sets the fill's
    /// error word. Launched once per fill, after every table's copy and before the completion
    /// word's, so every reader that waits for the completion word reads a checked fill.
    pub fn cuda_history_validate(args: *const c_void, layout: u32, stream: cudaStream_t) -> Error;
}
