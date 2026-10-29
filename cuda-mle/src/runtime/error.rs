//! CUDA error mapping: raw `cudaError_t` codes → `CudaError` (code + symbolic name + message).
//!
//! `CudaError::from_result` marks the calling thread as CUDA-touched
//! (`stream::mark_cuda_thread_used`) as a side effect, so `stream::CudaThreadCleanup` can drain
//! its per-thread stream at exit; `check` is a thin delegate, so direct callers of `from_result`
//! also mark the thread. Destructors and status queries bypass both and use raw codes instead:
//! `stream::CudaThreadCleanup::drop` to avoid re-entering TLS tracking during teardown, and
//! `CudaEvent::status` to keep `cudaErrorNotReady` out of the `Err` path.
//!
//! Also defines `MemoryError` and `MemCopyError`, wrapping `CudaError` with this crate's own
//! allocation/copy-precondition variants. Algorithm-level errors that wrap these
//! (e.g. `ProverError`, `WhirProverError`) live in crate-root `src/error.rs`.

use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use thiserror::Error;

#[link(name = "cudart")]
extern "C" {
    fn cudaGetErrorName(code: c_int) -> *const c_char;
    fn cudaGetErrorString(code: c_int) -> *const c_char;
}

/// Copies a C string the CUDA runtime handed back into an owned `String`.
fn owned_runtime_str(raw: *const c_char) -> String {
    if raw.is_null() {
        return String::from("Unknown CUDA error (null pointer)");
    }
    // SAFETY: non-null was checked above; the runtime returns NUL-terminated static strings from
    // `cudaGetErrorName`/`cudaGetErrorString`.
    unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned()
}

/// Symbolic name of a CUDA status code, such as `cudaErrorMemoryAllocation`.
pub(crate) fn cuda_error_name(code: i32) -> String {
    // SAFETY: defined for every `i32`, unrecognised codes included; never returns a dangling
    // pointer.
    owned_runtime_str(unsafe { cudaGetErrorName(code) })
}

/// Human-readable description of a CUDA status code, such as "out of memory".
pub(crate) fn cuda_error_description(code: i32) -> String {
    // SAFETY: as for `cuda_error_name`.
    owned_runtime_str(unsafe { cudaGetErrorString(code) })
}

/// Non-success CUDA status: the raw code plus the runtime's name and description for it.
#[derive(Error, Debug)]
#[error("{message} ({name})")]
pub struct CudaError {
    pub code: i32,
    pub name: String,
    pub message: String,
}

/// `cudaErrorMemoryAllocation`.
const CUDA_ERROR_MEMORY_ALLOCATION: i32 = 2;

impl CudaError {
    /// Builds the error for a non-zero status code.
    pub fn new(code: i32) -> Self {
        let name = cuda_error_name(code);
        let message = cuda_error_description(code);
        Self {
            code,
            name,
            message,
        }
    }

    /// `Ok` for `cudaSuccess` (0), otherwise the corresponding `CudaError`.
    pub fn from_result(code: i32) -> Result<(), Self> {
        crate::runtime::stream::mark_cuda_thread_used();
        match code {
            0 => Ok(()),
            failed => Err(Self::new(failed)),
        }
    }

    /// Whether this is an out-of-device-memory failure.
    #[inline]
    pub fn is_out_of_memory(&self) -> bool {
        self.code == CUDA_ERROR_MEMORY_ALLOCATION
    }
}

/// Shorthand for [`CudaError::from_result`].
#[inline]
pub fn check(code: i32) -> Result<(), CudaError> {
    CudaError::from_result(code)
}

#[derive(Error, Debug)]
pub enum MemoryError {
    #[error(transparent)]
    Cuda(#[from] CudaError),

    #[error("free was called with a null pointer")]
    NullPointer,

    #[error("memory manager lock is poisoned")]
    LockError,

    #[error("pointer is not in the allocation table")]
    InvalidPointer,
}

// Five variants were removed from `MemoryError`, all with zero constructors anywhere in
// the workspace: `UntrackedPointer` (its semantics were folded into `InvalidPointer`),
// `InvalidMemorySize`, and the self-managed-pool leftovers `RequestedExceedsVaChunk`,
// `ReserveFailed` and `OutOfMemory { requested, available }`. The last one described a *sub*-
// allocator running out of a reservation it owned, which no longer exists: driver-level OOM is
// already classified through `MemoryError::Cuda` / `CudaError::is_out_of_memory`, which is what a
// future fallible `DeviceBuffer::with_capacity` should surface.

#[derive(Error, Debug)]
pub enum MemCopyError {
    #[error(transparent)]
    Cuda(#[from] CudaError),
    #[error("{operation}: source has {src_len} elements but destination has {dst_len}")]
    SizeMismatch {
        operation: &'static str,
        src_len: usize,
        dst_len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_code_maps_to_name_and_message() {
        let e = CudaError::new(2); // cudaErrorMemoryAllocation
        assert_eq!(e.code, 2);
        assert_eq!(e.name, "cudaErrorMemoryAllocation");
        assert!(e.is_out_of_memory());
        assert!(!e.message.is_empty());
    }

    #[test]
    fn check_maps_success_and_failure() {
        assert!(check(0).is_ok());
        let e = check(1).unwrap_err(); // cudaErrorInvalidValue
        assert_eq!(e.code, 1);
        assert_eq!(e.name, "cudaErrorInvalidValue");
    }

    #[test]
    fn unknown_code_does_not_panic() {
        let e = CudaError::new(999_999);
        assert_eq!(e.code, 999_999);
        assert!(!e.name.is_empty()); // runtime returns "unrecognized error code", not a crash
    }
}
