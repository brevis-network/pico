//! AOT Emulator Implementation
//!
//! This module provides the core AotEmulatorCore struct for executing AOT-compiled
//! RISC-V programs. It combines AOT-compiled blocks with an interpreter fallback
//! for dynamic code paths.
//!
//! # Usage Pattern
//!
//! AOT dispatch logic is generated into a separate crate which provides
//! extension traits for execution (e.g. `run()` and `next_state_batch()`).

mod chunk;
mod clock;
mod constants;
mod instructions_base;
mod instructions_no_count;
mod instructions_tracked;
mod memory;
mod registers;
mod snapshot;
mod state;
mod types;
mod unconstrained;

pub use state::AotEmulatorCore;
