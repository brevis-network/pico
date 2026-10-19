use std::{marker::PhantomData, sync::Arc};

use p3_matrix::dense::RowMajorMatrix;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    keygen::types::MultiStarkProvingKey,
    poly::matrix::{ColMajorMatrix, MatrixDimensions},
    prover::{
        stacked_pcs::StackedPcsData, AirProvingContext, CommittedTraceData,
        DeviceMultiStarkProvingKey, ProvingContext, ReferenceColMajorBackend,
    },
    StarkProtocolConfig,
};

/// Associated types needed by the prover, in the form of buffers and views,
/// specific to a specific hardware backend.
///
/// Memory allocation and copying is not handled by this trait.
pub trait ProverBackend {
    /// Extension field degree for the challenge field `Self::Challenge` over base field
    /// `Self::Val`.
    const CHALLENGE_EXT_DEGREE: u8;
    // ==== Host Types ====
    /// Base field type, on host.
    type Val: Copy + Send + Sync + Serialize + DeserializeOwned;
    /// Challenge field (extension field of base field), on host.
    type Challenge: Copy + Send + Sync + Serialize + DeserializeOwned;
    /// Single commitment on host.
    // Commitments are small in size and need to be transferred back to host to be included in
    // proof.
    type Commitment: Clone + Send + Sync + Serialize + DeserializeOwned;

    // ==== Device Types ====
    /// Single matrix buffer on device together with dimension metadata. Owning this means nothing
    /// else has a shared reference to the buffer.
    type Matrix: MatrixDimensions + Send + Sync;
    /// Backend specific type for any pre-computed data associated with a single AIR. For example,
    /// it may contain prover-specific precomputations based on the AIR constraints (but
    /// independent from any trace data).
    ///
    /// This is a live device seam: the reference and CPU backends cache their pruned interaction
    /// evaluation plans here, and GPU backends may store their own prover precomputations. Do not
    /// delete it as dead.
    type OtherAirData: Send + Sync;
    /// Owned buffer for the preimage of a PCS commitment on device, together with any metadata
    /// necessary for computing opening proofs.
    ///
    /// For example, multiple buffers for LDE matrices, their trace domain sizes, and pointer to
    /// mixed merkle tree.
    type PcsData: Send + Sync;
}

pub trait ProverDevice<PB: ProverBackend, TS>:
    TraceCommitter<PB> + MultiRapProver<PB, TS> + OpeningProver<PB, TS>
{
    type Error: 'static
        + std::error::Error
        + Send
        + Sync
        + From<<Self as TraceCommitter<PB>>::Error>
        + From<<Self as MultiRapProver<PB, TS>>::Error>
        + From<<Self as OpeningProver<PB, TS>>::Error>;
}

/// Provides functionality for committing to a batch of trace matrices, possibly of different
/// heights.
pub trait TraceCommitter<PB: ProverBackend> {
    type Error: std::fmt::Debug;
    fn commit(&self, traces: &[&PB::Matrix]) -> Result<(PB::Commitment, PB::PcsData), Self::Error>;
}

/// This trait is responsible for all proving steps to prove a collection of trace matrices
/// satisfies all constraints of a Randomized AIR with Preprocessing. Such constraints include AIR
/// constraints as well as bus balancing constraints for interactions between AIRs. These
/// constraints may be grouped into challenge phases, where new randomness is sampled between phases
/// via Fiat-Shamir (which would involve committing to more data).
///
/// This trait is _not_ responsible for committing to the trace matrices or for proving polynomial
/// openings with respect to the committed trace matrices.
pub trait MultiRapProver<PB: ProverBackend, TS> {
    /// The partial proof is the proof that the trace matrices satisfy all constraints assuming that
    /// certain polynomial opening claims are validated. In other words, it is a proof that reduces
    /// the constraint satisfaction claim to certain polynomial opening claims.
    type PartialProof: Clone + Send + Sync + Serialize + DeserializeOwned;
    /// Other artifacts of the proof (e.g., sampled randomness) that may be passed to later stages
    /// of the protocol.
    type Artifacts;

    type Error: std::fmt::Debug;

    fn prove_rap_constraints(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<PB>,
        ctx: &ProvingContext<PB>,
    ) -> Result<(Self::PartialProof, Self::Artifacts), Self::Error>;
}

/// This trait is responsible for proving the evaluation claims of a collection of polynomials at a
/// collection of points. The opening point may be the same across polynomials. The polynomials may
/// be defined over different domains and are hence of "mixed" nature. The polynomials are already
/// committed and provided in their committed form.
pub trait OpeningProver<PB: ProverBackend, TS> {
    /// PCS opening proof on host. This should not be a reference.
    type OpeningProof: Clone + Send + Sync + Serialize + DeserializeOwned;
    type OpeningPoints;

    type Error: std::fmt::Debug;

    /// Computes the opening proof that reduces the polynomial evaluation claims (at `points`) for
    /// all committed traces to a single WHIR proof.
    ///
    /// `common_main_pcs_data` is the `PcsData` for the collection of common main trace matrices; it
    /// is owned by the function and may be mutated. The preprocessed and cached-main `PcsData`
    /// travel with `mpk` and `ctx`.
    fn prove_openings(
        &self,
        transcript: &mut TS,
        mpk: &DeviceMultiStarkProvingKey<PB>,
        ctx: ProvingContext<PB>,
        common_main_pcs_data: PB::PcsData,
        points: Self::OpeningPoints,
    ) -> Result<Self::OpeningProof, Self::Error>;
}

/// The *host* interchange backend for drivers that hold row-major trace-generation output.
///
/// A type-level marker, not a device: it has no [`ProverDevice`] impl, and no real device pairs
/// `RowMajorMatrix` traces with the host [`StackedPcsData`] as it does. That lets the
/// `transport_row_major_*` methods below name a row-major host context without naming any
/// device's types.
#[derive(Clone, Copy)]
pub struct RowMajorHostBackend<SC: StarkProtocolConfig>(PhantomData<SC>);

impl<SC: StarkProtocolConfig> RowMajorHostBackend<SC> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<SC: StarkProtocolConfig> Default for RowMajorHostBackend<SC> {
    fn default() -> Self {
        Self::new()
    }
}

impl<SC: StarkProtocolConfig> ProverBackend for RowMajorHostBackend<SC> {
    const CHALLENGE_EXT_DEGREE: u8 = SC::D_EF as u8;

    type Val = SC::F;
    type Challenge = SC::EF;
    type Commitment = SC::Digest;
    type Matrix = RowMajorMatrix<SC::F>;
    type OtherAirData = ();
    type PcsData = StackedPcsData<SC::F, SC::Digest>;
}

/// Trait to manage data transport of prover types from host to device.
pub trait DeviceDataTransporter<SC, PB>
where
    SC: StarkProtocolConfig,
    PB: ProverBackend<Val = SC::F, Challenge = SC::EF, Commitment = SC::Digest>,
{
    /// Transport the proving key to the device, filtering for only the provided `air_ids`.
    fn transport_pk_to_device(
        &self,
        mpk: &MultiStarkProvingKey<SC>,
    ) -> DeviceMultiStarkProvingKey<PB>;

    fn transport_matrix_to_device(&self, matrix: &ColMajorMatrix<SC::F>) -> PB::Matrix;

    /// Transport a committed PCS preimage from host to device.
    ///
    /// The canonical host format is the column-major [`StackedPcsData`]; each backend converts it
    /// into its own [`PcsData`](ProverBackend::PcsData) (the CPU device transposes the Merkle
    /// backing to row-major while reusing the digest layers verbatim). `pcs_data` is assumed to
    /// have been previously computed from the corresponding trace.
    fn transport_pcs_data_to_device(
        &self,
        pcs_data: &StackedPcsData<SC::F, SC::Digest>,
    ) -> PB::PcsData;

    fn transport_committed_trace_data_to_device(
        &self,
        committed_trace: &CommittedTraceData<ReferenceColMajorBackend<SC>>,
    ) -> CommittedTraceData<PB> {
        let trace = self.transport_matrix_to_device(&committed_trace.trace);
        let data = self.transport_pcs_data_to_device(committed_trace.data.as_ref());

        CommittedTraceData {
            commitment: committed_trace.commitment,
            trace,
            data: Arc::new(data),
        }
    }

    fn transport_proving_ctx_to_device(
        &self,
        ctx: &ProvingContext<ReferenceColMajorBackend<SC>>,
    ) -> ProvingContext<PB> {
        let per_trace = ctx
            .per_trace
            .iter()
            .map(|(air_idx, trace_ctx)| {
                let common_main = self.transport_matrix_to_device(&trace_ctx.common_main);
                let cached_mains = trace_ctx
                    .cached_mains
                    .iter()
                    .map(|cd| self.transport_committed_trace_data_to_device(cd))
                    .collect();
                let device_ctx = AirProvingContext::new(
                    cached_mains,
                    common_main,
                    trace_ctx.public_values.clone(),
                );
                (*air_idx, device_ctx)
            })
            .collect();
        ProvingContext::new(per_trace)
    }

    // The methods above take the column-major host format; the three below mirror them for a
    // `ProvingContext<RowMajorHostBackend<SC>>`, which is what real drivers hold. Provided rather
    // than required, so existing implementations keep compiling.

    /// Transport a row-major host matrix to the device.
    ///
    /// The default routes through the column-major primitive, which costs one transpose. Devices
    /// with a row-major native matrix override this.
    fn transport_row_major_matrix_to_device(&self, matrix: &RowMajorMatrix<SC::F>) -> PB::Matrix {
        self.transport_matrix_to_device(&ColMajorMatrix::from_row_major(matrix))
    }

    /// Row-major twin of [`transport_committed_trace_data_to_device`].
    ///
    /// [`transport_committed_trace_data_to_device`]:
    ///     DeviceDataTransporter::transport_committed_trace_data_to_device
    fn transport_row_major_committed_trace_data_to_device(
        &self,
        committed_trace: &CommittedTraceData<RowMajorHostBackend<SC>>,
    ) -> CommittedTraceData<PB> {
        let trace = self.transport_row_major_matrix_to_device(&committed_trace.trace);
        let data = self.transport_pcs_data_to_device(committed_trace.data.as_ref());

        CommittedTraceData {
            commitment: committed_trace.commitment,
            trace,
            data: Arc::new(data),
        }
    }

    /// Row-major twin of [`transport_proving_ctx_to_device`]. Transports `cached_mains` too.
    ///
    /// [`transport_proving_ctx_to_device`]: DeviceDataTransporter::transport_proving_ctx_to_device
    fn transport_row_major_proving_ctx_to_device(
        &self,
        ctx: &ProvingContext<RowMajorHostBackend<SC>>,
    ) -> ProvingContext<PB> {
        let per_trace = ctx
            .per_trace
            .iter()
            .map(|(air_idx, trace_ctx)| {
                let common_main = self.transport_row_major_matrix_to_device(&trace_ctx.common_main);
                let cached_mains = trace_ctx
                    .cached_mains
                    .iter()
                    .map(|cd| self.transport_row_major_committed_trace_data_to_device(cd))
                    .collect();
                let device_trace_ctx = AirProvingContext::new(
                    cached_mains,
                    common_main,
                    trace_ctx.public_values.clone(),
                );
                (*air_idx, device_trace_ctx)
            })
            .collect();
        ProvingContext::new(per_trace)
    }

    // ==================================================================================
    // Device-to-Host methods below should only be used for testing / debugging purposes.
    // ==================================================================================

    /// Transport a device matrix to host. This should only be used for testing / debugging
    /// purposes.
    fn transport_matrix_from_device_to_host(&self, matrix: &PB::Matrix) -> ColMajorMatrix<SC::F>;
}
