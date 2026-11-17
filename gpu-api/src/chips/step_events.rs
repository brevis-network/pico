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

/// `cuda_memory_local_generate_extra_record_and_main_u64`'s steps, in `riscv_memory_local.cuh`'s
/// `step` order.
pub const MEMORY_LOCAL_STEPS: [&str; 2] = ["memset", "fill"];
