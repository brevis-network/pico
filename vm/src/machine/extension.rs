//! `BinomialExtension` was relocated to `pico-mle-core` (it is referenced by `ChipBaseBuilder`'s
//! default methods, which moved with the `ChipBuilder` stack). Re-exported here so the ~18
//! `crate::machine::extension::BinomialExtension` call sites keep resolving unchanged.
// Re-export shim: this is literally `pico_mle_core::extension::BinomialExtension`, used identically
// by both backends — so this is not FRI-gated.
//
// TODO: repoint the ~18 users to `pico_mle_core::extension` and delete this re-export. Mechanical
// rename, no FRI dependency.
pub use pico_mle_core::extension::BinomialExtension;
