//! Row-major CPU prover backend for the MLE proof system.
//!
//! This crate provides [`CpuBackend`] and [`CpuDevice`], a prover backend that uses
//! row-major matrix layout for the constraint evaluation hot path (logup_zerocheck).
//! This gives significantly better cache locality and enables SIMD vectorization
//! via plonky3's `PackedField`.
//!
//! At PCS boundaries (trace commitment, WHIR opening), the row-major matrices are
//! converted to column-major format, which is a one-time cost.
//!
//! It is a plug-in over the [`pico_mle_core`] prover HAL, which owns the protocol contract and the
//! column-major [`ReferenceDevice`](pico_mle_core::prover::ReferenceDevice) this device is
//! differentially tested against.

// `derive_new::new` (0.7.0, the latest release) builds its constructor's `Self { field: field }`
// out of each field's own span, and the clippy of nightly-2026-09-27 takes that for code written
// here.
#![allow(clippy::redundant_field_names)]

mod backend;
mod device;
pub mod engine;
pub mod logup_zerocheck;
pub mod merkle;
pub mod pcs_data;
mod stacked_reduction;
pub mod whir;

pub use backend::CpuBackend;
pub use device::CpuDevice;
pub use engine::{KbCpuTranscript, KoalaBearPoseidon2CpuEngine};
