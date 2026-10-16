//! Protocol configs that cannot live in `pico-mle-core`.
//!
//! The generic MLE configs (`koala_bear_poseidon2`, the `SystemParams` presets, the `Hasher` /
//! `MultiFieldHasher` building blocks) live in [`pico_mle_core::config`]. This module exists for
//! configs that need a primitive from `vm`, which `pico-mle-core` cannot depend on: the dependency
//! runs `vm -> pico-mle-cpu -> pico-mle-core`.
//!
//! Today that is exactly one config: the outer ("embed") config, which is pinned to
//! [`pico_poseidon2bn254_init`](crate::primitives::pico_poseidon2bn254_init) — the width-3 BN254
//! Poseidon2 permutation the gnark `Permute` chip implements. Its round constants come from
//! `zkhash`, a dependency that does not belong under the protocol core.

// Outer ("embed") config: a KoalaBear STARK whose PCS commitments and Fiat–Shamir transcript run
// over BN254 Poseidon2. Documented in the module itself.
#[cfg(feature = "multi-field-transcript")]
pub mod koala_bear_bn254_poseidon2;
