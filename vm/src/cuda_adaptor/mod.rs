//! GPU resource pools shared by the RISC-V trace generators and the MLE backend.
//!
//! The legacy FRI GPU adaptor that used to live here (FRI commit / open, quotient, transpose,
//! codegen) was removed together with the FRI proving path; see tag `legacy-fri-last`.

pub mod resource_pool;

pub use resource_pool::{
    mem_pool::{create_ctx as create_mem_pool, get_global_mem_pool},
    stream_pool::{
        create_stream, get_global_stream_pool, release_stats, streams_created, SyncStreamPool,
    },
};

/// Exits with a clear message when no CUDA device is usable. A `cuda` build has no CPU fallback,
/// so failing here beats an opaque driver error from deep inside the first allocation.
pub fn require_cuda_device() {
    match cudart::device::get_device_count() {
        Ok(count) if count > 0 => {}
        result => {
            eprintln!(
                "this pico build uses the GPU (`cuda` feature) but found no usable CUDA device \
                 ({result:?}); rebuild without `--features cuda` (or with PICO_CUDA=0) to prove \
                 on the CPU"
            );
            std::process::exit(1);
        }
    }
}
