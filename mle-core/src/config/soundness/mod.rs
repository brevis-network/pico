//! Round-by-round soundness of the MLE proof system.
//!
//! Every interactive round (LogUp-GKR, ZeroCheck with univariate skip, constraint batching,
//! stacked reduction, and each WHIR round) is charged its own cheating probability; a round's
//! error sources add up, and the proof's provable bits are those of its weakest round.
//! `calculator` holds the formulas (references: WHIR, ePrint 2024/1586; [BCHKS25], ECCC TR25-169;
//! the LogUp soundness note cited at `SoundnessCalculator::logup_soundness`). `vk` reads the
//! calculator's circuit-shape inputs off a verifying key, so a key can be scored after keygen.

use p3_field::PrimeField64;

use crate::config::StarkProtocolConfig;

mod calculator;
mod vk;

pub use calculator::*;
pub use vk::{
    admit_production_vk, log_vk_soundness, UnderBudgetError, VkShape, PRODUCTION_SECURITY_BITS,
    WORST_CASE_N_LOGUP,
};

/// Which degree bound the list-decoding term of this build's calculator uses, as the soundness
/// manifest labels it: the components of a list-decoding preset differ between the two.
pub const DEGREE_BOUND: &str = if cfg!(feature = "soundness-bchks25-optimized") {
    "bchks25-optimized"
} else {
    "closed-form"
};

/// Order `p` of the configured base field.
///
/// Not part of the public API: exposed only so concrete configs can specialize it without
/// restating the formula.
#[doc(hidden)]
pub fn base_field_order<SC: StarkProtocolConfig>() -> f64 {
    SC::F::ORDER_U64 as f64
}

/// Number of bits in the challenge (extension) field: `D_EF * log2(|F|)`.
///
/// Derived from the configured extension degree (`StarkProtocolConfig::D_EF`), so it tracks
/// automatically if the extension field changes.
///
/// Not part of the public API: exposed only so concrete configs can specialize it without
/// restating the formula.
#[doc(hidden)]
pub fn challenge_field_bits<SC: StarkProtocolConfig>() -> f64 {
    SC::D_EF as f64 * base_field_order::<SC>().log2()
}
