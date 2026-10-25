//! `#[repr(C)]` context structs of the logup / zerocheck kernels. Their layouts must match the
//! structs of the same names in pico-gpu's `src/prover/logup_zerocheck/`; the FFI bindings that
//! take them are in [`super::logup_zerocheck_kb`].

use std::ffi::c_void;

use super::*;
use crate::monomial::{MonomialHeader, PackedVar};

/// Device pointer to one trace matrix together with its column count.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MainMatrixPtrs<T> {
    pub data: *const T,
    pub air_width: u32,
}

/// Inputs shared by every expression evaluator: selector columns, the preprocessed and main
/// trace matrices, and the public values.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct EvalCoreCtx {
    pub d_selectors: *const EF,
    pub d_preprocessed: MainMatrixPtrs<EF>,
    /// Device array with one entry per main-trace partition.
    pub d_main: *const MainMatrixPtrs<EF>,
    pub d_public: *const F,
}

/// Maps a block of a batched launch to the AIR it works on.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BlockCtx {
    pub local_block_idx_x: u32,
    /// Index into the launch's own array of `ZerocheckCtx` / `LogupCtx` entries, i.e. a position
    /// local to this batch, NOT the AIR's index in the proving key.
    pub air_idx: u32,
}

/// Per-AIR inputs of the batched zerocheck DAG evaluator.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ZerocheckCtx {
    pub eval_ctx: EvalCoreCtx,
    /// Scratch space for intermediate node values.
    pub d_intermediates: *mut EF,
    pub num_y: u32,
    pub d_eq_xi: *const EF,
    /// Encoded rule list of the constraint DAG (opaque to Rust).
    pub d_rules: *const c_void,
    pub rules_len: usize,
    pub d_used_nodes: *const usize,
    pub used_nodes_len: usize,
    /// Intermediate-buffer size the encoded rules require.
    pub buffer_size: u32,
}

/// Per-AIR inputs of the batched logup DAG evaluator.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LogupCtx {
    pub eval_ctx: EvalCoreCtx,
    /// Scratch space for intermediate node values.
    pub d_intermediates: *mut EF,
    pub num_y: u32,
    pub d_eq_xi: *const EF,
    pub d_challenges: *const EF,
    pub d_eq_3bs: *const EF,
    /// Encoded rule list of the interaction DAG (opaque to Rust).
    pub d_rules: *const c_void,
    pub rules_len: usize,
    pub d_used_nodes: *const usize,
    pub d_pair_idxs: *const u32,
    pub used_nodes_len: usize,
    /// Intermediate-buffer size the encoded rules require.
    pub buffer_size: u32,
}

/// Per-AIR inputs of the batched monomial (zerocheck) evaluator.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MonomialAirCtx {
    pub d_headers: *const MonomialHeader,
    pub d_variables: *const PackedVar,
    /// One lambda combination per monomial, computed ahead of the launch.
    pub d_lambda_combinations: *const EF,
    pub num_monomials: u32,
    pub eval_ctx: EvalCoreCtx,
    pub d_eq_xi: *const EF,
    pub num_y: u32,
}

/// Per-AIR state of the batched logup monomial evaluator that the numerator and denominator
/// passes share.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LogupMonomialCommonCtx {
    pub eval_ctx: EvalCoreCtx,
    pub d_eq_xi: *const EF,
    /// Computed ahead of the launch: sum over i of
    /// `beta[message_len_i] * (bus_idx[i] + 1) * eq_3bs[i]`.
    pub bus_term_sum: EF,
    pub num_y: u32,
    pub mono_blocks: u32,
}

/// Per-AIR monomial list of the batched logup evaluator (used for either the numerator or the
/// denominator).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LogupMonomialCtx {
    pub d_headers: *const MonomialHeader,
    pub d_variables: *const PackedVar,
    pub d_combinations: *const EF,
    pub num_monomials: u32,
}
