//! The VM and protocol types this crate names.
//!
//! `Kb` is the field and `Sc` is the protocol config. Both are the same in the CPU and `cuda`
//! builds, where only the engine behind them differs, which is what lets this crate be one source
//! for both. No engine type is named anywhere in the crate.

pub(crate) use pico_vm::mle::machine::riscv::{Kb, Sc};

/// The protocol proof, aliased because [`crate::Proof`] is the name a user of this crate reaches
/// for and the two would otherwise collide in every file that handles both.
pub(crate) type InnerProof = pico_mle_core::proof::Proof<Sc>;

pub(crate) type VerifyingKey = pico_mle_core::keygen::types::MultiStarkVerifyingKey<Sc>;
