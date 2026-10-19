//! MLE/WHIR STARK backend core (KoalaBear-only).
//!
//! The protocol core of the MLE backend — config, transcript, symbolic AIR, interaction model,
//! polynomial primitives, PCS/sumcheck/logup/WHIR prover & verifier, the col-major reference
//! device, and the `StarkEngine`. The optimized row-major CPU device is the sibling `pico-mle-cpu`
//! crate; the brevis RISCV chip glue and the recursion (Convert) layer stay in `vm/src/mle`.

// `derive_new::new` (0.7.0, the latest release) builds its constructor's `Self { field: field }`
// out of each field's own span, and the clippy of nightly-2026-09-27 takes that for code written
// here.
#![allow(clippy::redundant_field_names)]

// Re-export the Plonky3 crates the backend relies on so vendored `p3_*` paths resolve under
// `crate::p3_*`. The set is complete with respect to this crate's public signatures, so device
// backends need not pin p3 themselves.
pub use p3_air;
pub use p3_challenger;
pub use p3_dft;
pub use p3_field;
pub use p3_koala_bear;
pub use p3_matrix;
pub use p3_maybe_rayon;
pub use p3_poseidon2;
pub use p3_symmetric;
pub use p3_util;

pub mod air;
pub mod builder;
pub mod canonical_serde;
pub mod config;
pub mod engine;
pub mod extension;
pub mod interaction;
pub mod keygen;
pub mod lookup;
pub mod poly;
pub mod protocol;
pub mod prover;
pub mod transcript;
pub mod utils;
pub mod verifier;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// Explicit rather than globbed, so each type has exactly one canonical root path.
pub use air::any_air::{get_air_name, AirRef, AnyAir, BaseAirWithPublicValues, PartitionedBaseAir};
#[cfg(feature = "multi-field-transcript")]
pub use config::multi_field_packing;
pub use config::{
    compress_params_with_100_bits_security, embed_params_with_100_bits_security, hasher,
    recursion_params_with_100_bits_security, riscv_params_with_100_bits_security, soundness, Com,
    ProximityRegime, StarkProtocolConfig, SystemParams, Val, WhirConfig, WhirParams,
    WhirProximityStrategy, WhirRoundConfig, DEFAULT_COMPRESS_LOG_BLOWUP, DEFAULT_K_WHIR,
    DEFAULT_RECURSION_LOG_BLOWUP, DEFAULT_RISCV_LOG_BLOWUP, DEFAULT_RISCV_L_SKIP,
    DEFAULT_ROOT_LOG_BLOWUP, MAX_RISCV_LOG_STACKED_HEIGHT,
};
pub use engine::{ProverError, StarkEngine};
pub use protocol::{codec, proof};
pub use transcript::{FiatShamirTranscript, ReadOnlyTranscript, TranscriptHistory, TranscriptLog};
// `parizip!` is `#[macro_export]`ed in `utils`, which puts it at this crate's root automatically;
// no re-export is needed here (a `pub use crate::parizip` would self-collide).
