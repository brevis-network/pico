//! The step events the Global, Poseidon2 and local memory launchers take, defined in the kernel
//! library's `tracegen/common/step_events.cuh`: timing events the caller creates, which a launcher
//! records on the launch's own stream around each of its steps. A launcher given null records
//! nothing.

use cudart_sys::cudaEvent_t;

/// Step `i` is bracketed by `events[2 * i]` and `events[2 * i + 1]`. The launcher sets bit `i` of
/// `recorded` once both are recorded, so a step the launch skipped, or whose events failed to
/// record, reads as not run; `started` is the launcher's own.
#[repr(C)]
pub struct StepEvents {
    pub events: *const cudaEvent_t,
    pub steps: usize,
    pub started: u32,
    pub recorded: u32,
}

/// `cuda_riscv_global_generate_extra_record_and_main`'s steps, in `riscv_global.cuh`'s `step`
/// order. The scan's levels are its top call's: the block scan, the scan of the block sums with
/// any level below it, and the add of the block prefixes.
pub const RISCV_GLOBAL_STEPS: [&str; 6] = [
    "memset",
    "convert",
    "scan_blocks",
    "scan_sums",
    "scan_prefix",
    "accumulate",
];

/// `cuda_riscv_poseidon2_generate_main`'s steps, in `riscv_poseidon2.cuh`'s `step` order.
pub const RISCV_POSEIDON2_STEPS: [&str; 3] = ["memset", "permute", "pad"];

/// `cuda_memory_local_generate_extra_record_and_main_u64`'s steps, in `riscv_memory_local.cuh`'s
/// `step` order.
pub const MEMORY_LOCAL_STEPS: [&str; 2] = ["memset", "fill"];
