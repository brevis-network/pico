//! Base-layer polynomial & matrix primitives for the MLE/WHIR backend.
//!
//! This module owns the shared polynomial and matrix building blocks:
//!
//! - [`ntt`] — radix-2 DFT/NTT (serial and cached-twiddle; see its docs for DFT path ownership)
//! - [`mle`] / [`ple`] — multilinear / prismalinear extension polynomials
//! - [`eq`] — equality / Möbius / rotation kernels
//! - [`univariate`] — univariate polynomials + interpolation
//! - [`matrix`] — column-major matrices + views (+ [`matrix::MatrixDimensions`])
//! - [`row_major`] — row-major-native fold / sumcheck helpers
//!
//! Everything below `prover`/`verifier` depends on this tree; this tree depends on none of
//! them (one-way dependency).

pub mod eq;
pub mod matrix;
pub mod mle;
pub mod ntt;
pub mod ple;
pub mod row_major;
pub mod univariate;

pub use eq::{
    accumulate_scaled_eq_hypercube_base_field, accumulate_scaled_eq_hypercube_same_field,
    eq_sharp_uni_poly, eq_uni_poly, eval_eq_mle, eval_eq_prism, eval_eq_rot_cube,
    eval_eq_sharp_uni, eval_eq_uni, eval_eq_uni_at_one, eval_in_uni, eval_mle_evals_at_point,
    eval_mobius_eq_mle, eval_rot_kernel_prism, evals_eq_hypercube_par, evals_eq_hypercube_serial,
    evals_eq_hypercubes, evals_eq_hyperprism, evals_mobius_eq_hypercube, fill_eq_hypercube_evals,
    fill_scaled_eq_hypercube_evals,
};
pub use mle::Mle;
pub use ntt::SerialRadix2Dft;
pub use ple::{eval_to_coeff_rs_message, eval_to_coeff_rs_message_with_twiddles, Ple};
pub use row_major::{batch_fold_mle_evals_rm, fold_mle_evals_rm, sumcheck_round_poly_evals_rm};
pub use univariate::{
    horner_eval, interpolate_cubic_at_0123, interpolate_linear_at_01, interpolate_quadratic_at_012,
    Squarable, UnivariatePoly,
};
