//! AOT-compiled emulator for Fibonacci example
//!
//! This crate re-exports AotEmulatorCore from pico-aot-dispatch when the 'aot' feature is enabled.

// Common Pico types used by binaries.
pub use pico_vm::{
    compiler::riscv::program::Program,
    emulator::{opts::EmulatorOpts, riscv::state::RiscvEmulationState},
    machine::report::EmulationReport,
};

// AOT-only runtime surface.
#[cfg(feature = "aot")]
pub use pico_aot_dispatch::AotEmulatorCore;

#[cfg(feature = "aot")]
pub use aot_common::AotRun;

// Type alias for backwards compatibility
#[cfg(feature = "aot")]
pub type FibonacciEmulator = AotEmulatorCore;
