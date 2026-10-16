use thiserror::Error;

use crate::protocol::stacking::StackedPcsError;

/// Shared `ProverDevice::Error` for both prover devices (the col-major reference and the
/// row-major CPU device). They fail for the same reasons — stacked PCS, logup-zerocheck, or WHIR —
/// so one enum serves both, and the `#[from]` impls back each device's `?`.
#[derive(Error, Debug)]
pub enum HostProverError {
    #[error("Stacked PCS: {0}")]
    StackedPcs(#[from] StackedPcsError),
    #[error("LogupZerocheck: {0}")]
    LogupZerocheck(#[from] LogupZerocheckError),
    #[error("WHIR: {0}")]
    Whir(#[from] WhirProverError),
}

/// Errors from `sumcheck.rs`. Only the test-only reference sumcheck oracles
/// (`sumcheck_multilinear`/`sumcheck_prismalinear`) produce this, so it is gated to test builds.
#[cfg(test)]
#[derive(Error, Debug)]
pub enum SumcheckError {
    #[error("sumcheck_multilinear: round polynomial length {len} != 1")]
    MultilinearRoundPolyLen { len: usize },
    #[error("sumcheck_multilinear: final evaluation count {len} != 1")]
    MultilinearFinalEvalLen { len: usize },
    #[error("sumcheck_prismalinear: prism_dim {prism_dim} < l_skip {l_skip}")]
    PrismalinearDimTooSmall { prism_dim: usize, l_skip: usize },
    #[error("sumcheck_prismalinear: round polynomial length {len} != 1")]
    PrismalinearRoundPolyLen { len: usize },
    #[error("sumcheck_prismalinear: r.len() {r_len} != n + 1 = {expected}")]
    PrismalinearRLen { r_len: usize, expected: usize },
    #[error("sumcheck_prismalinear: final evaluation count {len} != 1")]
    PrismalinearFinalEvalLen { len: usize },
}

/// Errors from `logup_zerocheck/` module.
#[derive(Error, Debug)]
pub enum LogupZerocheckError {
    #[error("Stacked PCS: {0}")]
    StackedPcs(#[from] StackedPcsError),
    #[error("fractional_sumcheck: non-zero root sum in assert_zero mode")]
    NonZeroRootSum,
    #[error(
        "LogupZerocheckColMajor::new: preprocessed trace index {index} out of bounds for width {width}"
    )]
    PreprocessedIndexOutOfBounds { index: usize, width: usize },
    #[error("LogupZerocheckColMajor::new: main partition {part_index} col_index {col_index} >= width {width}")]
    MainPartitionIndexOutOfBounds {
        part_index: usize,
        col_index: usize,
        width: usize,
    },
    #[error("LogupZerocheckColMajor::new: public value index {index} out of bounds for len {len}")]
    PublicValueIndexOutOfBounds { index: usize, len: usize },
    #[error("interactions_layout.get returned None for (trace_idx={trace_idx}, interaction_idx={interaction_idx})")]
    InteractionsLayoutMissing {
        trace_idx: usize,
        interaction_idx: usize,
    },
    #[error("sumcheck_polys_eval: eq_ns is empty at round {round}")]
    EqNsEmpty { round: usize },
    #[error("sumcheck_polys_eval: eq_sharp_ns is empty at round {round}")]
    EqSharpNsEmpty { round: usize },
    #[error("extract_column_openings: mat_evals.pop() returned None")]
    MatEvalsPopNone,
    #[error("extract_column_openings: claim.len() {len} != 1")]
    ClaimLenNotOne { len: usize },
    #[error("prove_zerocheck_and_logup: r.len() {r_len} != n_max + 1 = {expected}")]
    RLenMismatch { r_len: usize, expected: usize },
}

/// Errors from `whir.rs`.
#[derive(Error, Debug)]
pub enum WhirProverError {
    #[error("Stacked PCS: {0}")]
    StackedPcs(#[from] StackedPcsError),
    #[error("prove_whir_opening: try_into failed for sumcheck poly evals")]
    TryIntoFailed,
    #[error("prove_whir_opening: tree height {tree_height} != expected {expected}")]
    TreeHeightMismatch { tree_height: usize, expected: usize },
    #[error("prove_whir_opening: rs_tree is None in whir_round > 0")]
    RsTreeNone,
    #[error("prove_whir_opening: tree width {width} != 1")]
    TreeWidthNotOne { width: usize },
    #[error("prove_whir_opening: z_0 is None (not last round)")]
    Z0None,
    #[error("prove_whir_opening: final_poly is None")]
    FinalPolyNone,
    #[error("prove_openings: u_prisma is empty (split_first failed)")]
    UPrismaEmpty,
}

#[cfg(test)]
mod tests {
    use p3_field::{ExtensionField, TwoAdicField};

    use super::*;
    use crate::{
        prover::{ProverDevice, ReferenceColMajorBackend, ReferenceDevice},
        FiatShamirTranscript, StarkProtocolConfig,
    };

    /// Compile-time check that the reference device keeps `HostProverError` as its
    /// `ProverDevice::Error`. Never called; fails to compile if `type Error` is repointed
    /// elsewhere. Each device carries the matching check for itself.
    #[allow(dead_code)]
    fn reference_device_uses_host_prover_error<SC, TS>(
        ref_err: <ReferenceDevice<SC> as ProverDevice<ReferenceColMajorBackend<SC>, TS>>::Error,
    ) -> HostProverError
    where
        SC: StarkProtocolConfig,
        SC::F: Ord,
        SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
        TS: FiatShamirTranscript<SC>,
    {
        ref_err
    }

    /// Each inner error `#[from]`-maps to exactly one variant (the mapping every device `?` uses);
    /// the exhaustive `match` breaks compilation if a variant is added or removed.
    #[test]
    fn each_inner_error_maps_to_its_own_variant() {
        let from_stacked = HostProverError::from(StackedPcsError::MerkleTreeNoRoot);
        let from_logup = HostProverError::from(LogupZerocheckError::NonZeroRootSum);
        let from_whir = HostProverError::from(WhirProverError::TryIntoFailed);

        assert!(matches!(from_stacked, HostProverError::StackedPcs(_)));
        assert!(matches!(from_logup, HostProverError::LogupZerocheck(_)));
        assert!(matches!(from_whir, HostProverError::Whir(_)));

        // Exhaustiveness guard (compile-time).
        for e in [from_stacked, from_logup, from_whir] {
            match e {
                HostProverError::StackedPcs(_)
                | HostProverError::LogupZerocheck(_)
                | HostProverError::Whir(_) => {}
            }
        }
    }
}
