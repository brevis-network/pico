use thiserror::Error;

use crate::{
    runtime::error::{CudaError, MemCopyError},
    sponge::GrindError,
    KernelError,
};

#[derive(Debug, Error)]
pub enum Round0PrepError {
    #[error("CUDA call failed: {0}")]
    Cuda(#[from] CudaError),
    #[error("host/device copy failed: {0}")]
    Mem(#[from] MemCopyError),
    #[error("stacked layout cannot be staged for round 0")]
    Layout,
}

#[derive(Debug, Error)]
pub enum Round0EvalError {
    #[error("CUDA call failed: {0}")]
    Cuda(#[from] CudaError),
    #[error("host/device copy failed: {0}")]
    Copy(#[from] MemCopyError),
    #[error("round-0 inputs do not match the expected layout")]
    Layout,
}

impl From<Round0PrepError> for Round0EvalError {
    fn from(prep: Round0PrepError) -> Self {
        match prep {
            Round0PrepError::Cuda(cause) => Round0EvalError::Cuda(cause),
            Round0PrepError::Mem(cause) => Round0EvalError::Copy(cause),
            Round0PrepError::Layout => Round0EvalError::Layout,
        }
    }
}

#[derive(Debug, Error)]
pub enum FractionalSumcheckError {
    #[error("GKR root does not sum to zero (p = {p}, q = {q})")]
    NonzeroRootSum { p: String, q: String },
    #[error("bit-reversal kernel failed: {0}")]
    BitReversal(CudaError),
    #[error("fraction tree build failed: {0}")]
    SegmentTree(CudaError),
    #[error("sumcheck round kernel failed: {0}")]
    ComputeRound(CudaError),
    #[error("column fold kernel failed: {0}")]
    FoldColumns(CudaError),
    #[error("eq hypercube evaluation failed: {0}")]
    EvalEqHypercube(KernelError),
    #[error("proof-of-work grinding failed: {0}")]
    Grind(#[from] GrindError),
    #[error("host/device copy failed: {0}")]
    Copy(#[from] MemCopyError),
}

#[derive(Debug, Error)]
pub enum InteractionGpuError {
    #[error("CUDA call failed: {0}")]
    Cuda(#[from] CudaError),
    #[error("host/device copy failed: {0}")]
    Copy(#[from] MemCopyError),
    #[error("interaction inputs do not match the expected layout")]
    Layout,
}

#[derive(Debug, Error)]
pub enum FoldPleError {
    #[error("CUDA call failed: {0}")]
    Cuda(#[from] CudaError),
    #[error("host/device copy failed: {0}")]
    Copy(#[from] MemCopyError),
    #[error("matrix dimensions are not valid for a PLE fold")]
    InvalidDimensions,
}

#[derive(Debug, Error)]
pub enum UnstackMatrixError {
    #[error("no matrix with index {mat_idx}")]
    MatrixNotFound { mat_idx: usize },
}
