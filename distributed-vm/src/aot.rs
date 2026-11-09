use pico_aot_dispatch::AOT;
use pico_aot_runtime::AotError;

/// Registers the generated AOT program. A refused one (the bootstrap stub, or code generated
/// against another codegen stamp) installs no factory, and `EmulatorOpts::bench_riscv_ops` then
/// leaves the snapshot thread on the interpreter, so the run is slower but its records the same.
/// A conflict leaves the program registered first in place, with AOT emulation on.
pub fn register() {
    match pico_aot_runtime::register(&AOT) {
        Ok(()) => {}
        Err(err @ AotError::Conflict { .. }) => {
            tracing::warn!("AOT emulation runs the program registered first, not this one: {err}")
        }
        Err(err) => tracing::warn!("AOT emulation is off, the snapshot thread interprets: {err}"),
    }
}
