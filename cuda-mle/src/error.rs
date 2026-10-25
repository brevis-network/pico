use thiserror::Error;

use crate::{
    logup_zerocheck::{
        FoldPleError, FractionalSumcheckError, InteractionGpuError, Round0EvalError,
    },
    runtime::error::{CudaError, MemCopyError},
    sponge::GrindError,
};

#[derive(Error, Debug)]
pub enum ProverError {
    #[error("host/device copy failed: {0}")]
    MemCopy(#[from] MemCopyError),
    #[error("stream synchronize failed: {0}")]
    CurrentStreamSync(CudaError),
    #[error("collapsing a strided matrix failed: {0}")]
    CollapseStrided(CudaError),
    #[error("trace stacking failed: {0}")]
    StackTraces(#[from] StackTracesError),
    #[error("Merkle commitment failed: {0}")]
    MerkleTree(#[from] MerkleTreeError),
    #[error("RS encoding failed: {0}")]
    RsCodeMatrix(#[from] RsCodeMatrixError),
    #[error("WHIR opening failed: {0}")]
    Whir(#[from] WhirProverError),
    #[error("stacked opening reduction failed: {0}")]
    StackedReduction(#[from] StackedReductionError),
    #[error("LogUp/zerocheck round failed: {0}")]
    LogupZerocheck(#[from] LogupZerocheckError),
}

#[derive(Error, Debug)]
pub enum StackedReductionError {
    #[error(transparent)]
    MemCopy(#[from] MemCopyError),
    #[error("NTT twiddle setup failed: {0}")]
    InitNttTwiddles(CudaError),
    #[error("eq segment evaluation failed: {0}")]
    EqEvalSegments(KernelError),
    #[error("zero-fill failed: {0}")]
    FillZero(CudaError),
    #[error("round-0 sumcheck kernel failed: {0}")]
    SumcheckRound0(CudaError),
    #[error("PLE fold kernel failed: {0}")]
    FoldPle(CudaError),
    #[error("k_rot initialisation from eq segments failed: {0}")]
    InitKRot(CudaError),
    #[error("vector-by-scalar multiply failed: {0}")]
    VectorScalarMul(CudaError),
    #[error("degenerate MLE sumcheck round failed: {0}")]
    SumcheckMleRoundDegenerate(CudaError),
    #[error("MLE sumcheck round failed: {0}")]
    SumcheckMleRound(CudaError),
    #[error("MLE fold failed: {0}")]
    FoldMle(CudaError),
    #[error("triangular MLE fold failed: {0}")]
    TriangularFoldMle(CudaError),
}

#[derive(Error, Debug)]
pub enum LogupZerocheckError {
    #[error(transparent)]
    MemCopy(#[from] MemCopyError),
    #[error("proof-of-work grinding failed: {0}")]
    Grind(GrindError),
    #[error("round-0 constraint evaluation failed: {0}")]
    Round0Eval(#[from] Round0EvalError),
    #[error("interaction evaluation failed: {0}")]
    InteractionEval(#[from] InteractionGpuError),
    #[error("GKR fractional sumcheck failed: {0}")]
    FractionalSumcheck(#[from] FractionalSumcheckError),
    #[error("PLE fold failed: {0}")]
    FoldPle(#[from] FoldPleError),
    #[error("lambda combination kernel failed: {0}")]
    LambdaCombinations(CudaError),
    #[error("LogUp combination kernel failed: {0}")]
    LogupCombinations(CudaError),
    #[error("MLE-round constraint evaluation failed: {0}")]
    MleConstraintEval(KernelError),
    #[error("MLE-round interaction evaluation failed: {0}")]
    MleInteractionEval(KernelError),
    #[error("eq layer evaluation failed: {0}")]
    EqEvalLayers(KernelError),
    #[error("round-0 selector fold failed: {0}")]
    FoldSelectorsRound0(CudaError),
    #[error("column interpolation failed: {0}")]
    InterpolateColumns(KernelError),
    #[error("batched MLE fold failed: {0}")]
    BatchFoldMle(CudaError),
    #[error("zero-fill failed: {0}")]
    FillZero(CudaError),
}

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error(transparent)]
    MemCopy(#[from] MemCopyError),
    #[error(
        "rows_per_query = {rows_per_query} exceeds the {max_rows_per_query} rows the CUDA row \
         hasher can take per query"
    )]
    UnsupportedRowsPerQuery {
        rows_per_query: usize,
        max_rows_per_query: usize,
    },
    #[error("row hashing (compressing) failed: {0}")]
    CompressingRowHashes(CudaError),
    #[error("compressing Merkle layer {layer} failed: {error}")]
    AdjacentCompressLayer { error: CudaError, layer: usize },
    #[error("digest-layer query kernel failed: {0}")]
    QueryDigestLayers(CudaError),
    #[error("row fetch from matrix {matrix_idx} failed: {error}")]
    MatrixGetRows { error: CudaError, matrix_idx: usize },
}

#[derive(Error, Debug)]
pub enum StackTracesError {
    #[error(transparent)]
    MemCopy(#[from] MemCopyError),
    #[error("wide expand-and-pad failed: {0}")]
    BatchExpandPadWide(CudaError),
    #[error("stack gather failed: {0}")]
    StackGather(CudaError),
    #[error("zero-fill failed: {0}")]
    FillZero(CudaError),
    #[error(
        "gather descriptors overlap at index {index}: the previous slice ends at {prev_end}, \
         after the next one starts at {dst_start}"
    )]
    GatherDescriptorOverlap {
        index: usize,
        prev_end: u64,
        dst_start: u64,
    },
}

#[derive(Error, Debug)]
pub enum RsCodeMatrixError {
    #[error(transparent)]
    MemCopy(#[from] MemCopyError),
    /// Merkle-layer failures on the streaming path reuse [`MerkleTreeError`] so that a streaming
    /// failure reports exactly what the monolithic path would — notably
    /// `AdjacentCompressLayer { layer }`, whose index the old index-less `CompressLayer` variant
    /// dropped.
    #[error(transparent)]
    MerkleTree(#[from] MerkleTreeError),
    #[error("stacking traces into the expanded buffer failed: {0}")]
    StackTraces(StackTracesError),
    #[error("expand-and-pad failed: {0}")]
    BatchExpandPad(CudaError),
    #[error("batched inverse NTT failed: {0}")]
    CustomBatchIntt(CudaError),
    #[error("MLE interpolation stages failed: {0}")]
    MleInterpolateStages(CudaError),
    #[error("bit reversal failed: {0}")]
    BitRev(CudaError),
    #[error("streaming column absorb failed: {0}")]
    AbsorbColumns(CudaError),
    #[error("streaming leaf-digest finalisation failed: {0}")]
    FinalizeLeaf(CudaError),
    #[error("streaming self-check: Merkle root differs from the monolithic path")]
    StreamRootMismatch,
    #[error("streaming open: row fetch failed: {0}")]
    OpenGetRows(CudaError),
    #[error("streaming open: gather pass A failed: {0}")]
    OpenPassA(CudaError),
    #[error("streaming open: row gather failed: {0}")]
    OpenGatherDot(CudaError),
    #[error("streaming self-check: opened rows differ from the monolithic path")]
    StreamOpenMismatch,
}

#[derive(Error, Debug)]
pub enum WhirProverError {
    #[error(transparent)]
    MemCopy(#[from] MemCopyError),
    #[error("Merkle commitment failed: {0}")]
    MerkleTree(MerkleTreeError),
    #[error("RS encoding failed: {0}")]
    RsCodeMatrix(RsCodeMatrixError),
    #[error("algebraic batching of traces failed: {0}")]
    AlgebraicBatch(CudaError),
    #[error("base-to-extension transpose failed: {0}")]
    Transpose(CudaError),
    #[error("extension MLE interpolation failed at step {step}: {error}")]
    MleInterpolate { error: CudaError, step: u32 },
    #[error("batched inverse NTT failed: {0}")]
    CustomBatchIntt(CudaError),
    #[error("eq hypercube evaluation failed: {0}")]
    EvalEq(KernelError),
    #[error("WHIR sumcheck round {round} of WHIR round {whir_round} failed: {error}")]
    SumcheckMleRound {
        error: CudaError,
        whir_round: usize,
        round: usize,
    },
    #[error("MLE fold in sumcheck round {round} of WHIR round {whir_round} failed: {error}")]
    FoldMle {
        error: CudaError,
        whir_round: usize,
        round: usize,
    },
    #[error("splitting the extension polynomial failed in WHIR round {whir_round}: {error}")]
    SplitExtPoly { error: CudaError, whir_round: usize },
    #[error("expand-and-pad failed in WHIR round {whir_round}: {error}")]
    BatchExpandPad { error: CudaError, whir_round: usize },
    #[error("polynomial evaluation failed in WHIR round {whir_round}: {error}")]
    EvalPolyAtPoint {
        error: KernelError,
        whir_round: usize,
    },
    #[error("moment accumulation failed in WHIR round {whir_round}: {error}")]
    WMomentsAccumulate { error: CudaError, whir_round: usize },
    #[error("mu proof-of-work grinding failed: {0}")]
    MuGrind(GrindError),
    #[error("folding proof-of-work grinding failed: {0}")]
    FoldingGrind(GrindError),
    #[error("query-phase proof-of-work grinding failed: {0}")]
    QueryPhaseGrind(GrindError),
}

/// Failure of a call that launches CUDA kernels and also copies memory.
#[derive(Error, Debug)]
pub enum KernelError {
    #[error("kernel launch failed: {0}")]
    Kernel(#[from] CudaError),
    #[error("host/device copy failed: {0}")]
    MemCopy(#[from] MemCopyError),
}
