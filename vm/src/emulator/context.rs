/// Context to run a program inside Pico Emulator.
#[derive(Clone, Default)]
pub struct EmulatorContext {
    /// The maximum number of cpu cycles to use for emulation.
    pub max_cycles: Option<u64>,
}
