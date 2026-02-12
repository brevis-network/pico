//! AOT Runtime Execution
//!
//! This module provides runtime types and utilities for executing AOT-compiled RISC-V programs.
//!
//! # Architecture
//!
//! The runtime is organized around these core concepts:
//!
//! - **`AotEmulatorCore`**: The core emulator struct with all base functionality
//! - **`NextStep`**: Control flow decision (Direct/Dynamic/Halt)
//! - **`BlockClock`**: Batched clock updates for performance
//!
//! # Usage Pattern
//!
//! Due to Rust's orphan rules, user crates must define a local wrapper type for the
//! generated AOT code to target:
//!
//! ```ignore
//! // In your crate's emulator.rs
//! use std::ops::{Deref, DerefMut};
//! pub use pico_aot_runtime::{AotEmulatorCore, NextStep, BlockClock};
//!
//! pub struct MyEmulator(pub AotEmulatorCore);
//!
//! impl Deref for MyEmulator {
//!     type Target = AotEmulatorCore;
//!     fn deref(&self) -> &Self::Target { &self.0 }
//! }
//!
//! impl DerefMut for MyEmulator {
//!     fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
//! }
//!
//! impl MyEmulator {
//!     pub fn new(program: Arc<Program>, input_stream: Vec<Vec<u8>>) -> Self {
//!         Self(AotEmulatorCore::new(program, input_stream))
//!     }
//! }
//!
//! // Use the generated dispatch crate to execute AOT blocks
//! // (see pico-aot-dispatch for the generated run/lookup entry points).
//! ```

mod dispatch;
pub mod emulator;
mod hook;
pub mod interpreter;
pub mod precompiles;
pub mod syscall;
pub mod types;

// Re-export core types
pub use dispatch::{lookup_block_fn, set_lookup_block_fn};
pub use emulator::AotEmulatorCore;
pub use types::{BlockClock, BlockFn, ClockUpdate, NextStep};
