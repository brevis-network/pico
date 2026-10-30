//! RISCV / recursion machines built on the MLE/WHIR backend.
//!
//! The `ChipBuilder` trait stack is implemented natively by the backend builders
//! (`SymbolicRapBuilder` in `air/symbolic`, `DebugConstraintBuilder` in `air/debug`).

/// AIR-trait wiring (preprocessed wrapper, `BaseAirWithPublicValues`, `PartitionedBaseAir`).
pub mod air;
pub mod apex;
pub mod combine;
pub mod convert;
pub mod deferred;
// Embed prover: re-proves a complete combine root under the outer BN254-hashed config.
#[cfg(feature = "multi-field-transcript")]
pub mod embed;
pub mod exe;
pub mod recursion;
pub mod riscv;
pub mod shape;
// Needs `pico-verifier/codec`, which a guest build leaves out.
#[cfg(not(target_os = "zkvm"))]
pub mod vk_bundle;
pub mod vk_map;
// Wrap artifact builder: embed proof -> gnark constraints + witness.
#[cfg(feature = "multi-field-transcript")]
pub mod wrap;
