use pico_aot_dispatch::AOT;

/// Registers the generated AOT program. A refused one (the bootstrap stub, or code generated
/// against another codegen stamp) installs no factory, and `EmulatorOpts::bench_riscv_ops` then
/// leaves the snapshot thread on the interpreter, so the run is slower but its records the same.
pub fn register() {
    if let Err(err) = pico_aot_runtime::register(&AOT) {
        tracing::warn!("AOT emulation is off, the snapshot thread interprets: {err}");
    }
}
