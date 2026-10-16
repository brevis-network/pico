use itertools::{izip, Itertools};
use p3_field::PrimeCharacteristicRing;
use p3_util::log2_strict_usize;
use tracing::{info, info_span, instrument};

#[cfg(feature = "metrics")]
use crate::prover::metrics::trace_metrics;
use crate::{
    poly::matrix::MatrixDimensions,
    proof::{BatchConstraintProof, GkrProof, Proof, StackingProof, TraceVData, WhirProof},
    FiatShamirTranscript, StarkProtocolConfig,
};

pub mod error;
mod hal;
mod logup_zerocheck;
pub mod metrics;
mod reference;
pub mod stacked_pcs;
pub mod stacked_reduction;
pub mod sumcheck;
mod types;
pub mod whir;

pub use error::{HostProverError, LogupZerocheckError, WhirProverError};
pub use hal::{
    DeviceDataTransporter, MultiRapProver, OpeningProver, ProverBackend, ProverDevice,
    RowMajorHostBackend, TraceCommitter,
};
pub use logup_zerocheck::{
    evaluator, fractional_sumcheck_gkr, prove_zerocheck_and_logup, ColMajorEvalHelper,
    LogupZerocheckColMajor, ZerocheckLogupProof,
};
pub use reference::{ReferenceColMajorBackend, ReferenceDevice};
pub use types::{
    AirProvingContext, CommittedTraceData, DeviceMultiStarkProvingKey, DeviceStarkProvingKey,
    ProvingContext,
};

/// Trait for STARK/SNARK proving at the highest abstraction level.
pub trait Prover {
    type ProvingKeyView<'a>
    where
        Self: 'a;
    type ProvingContext<'a>
    where
        Self: 'a;
    type Proof;
    type Error;

    /// The prover should own the challenger, whose state mutates during proving.
    fn prove<'a>(
        &'a mut self,
        pk: Self::ProvingKeyView<'a>,
        ctx: Self::ProvingContext<'a>,
    ) -> Result<Self::Proof, Self::Error>;
}

pub struct Coordinator<SC: StarkProtocolConfig, PB: ProverBackend, PD, TS> {
    // Only same-crate `engine`/HAL code touches these directly; external callers construct via
    // `Coordinator::new` and drive proving through the `Prover` trait.
    pub(crate) device: PD,
    pub(crate) transcript: TS,
    // `PB` is fixed by the `ProverDevice<PB, TS>` bound on `PD`; it is not stored, since proving
    // reads all trace/PCS data from `device` and never from a backend value.
    _marker: std::marker::PhantomData<(SC, PB)>,
}

impl<SC: StarkProtocolConfig, PB: ProverBackend, PD, TS> Coordinator<SC, PB, PD, TS> {
    pub fn new(device: PD, transcript: TS) -> Self {
        Self {
            device,
            transcript,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<SC, PB, PD, TS> Prover for Coordinator<SC, PB, PD, TS>
where
    SC: StarkProtocolConfig,
    PB: ProverBackend<Val = SC::F, Challenge = SC::EF, Commitment = SC::Digest>,
    PD: ProverDevice<PB, TS>,
    PD::Artifacts: Into<PD::OpeningPoints>,
    PD::PartialProof: Into<(GkrProof<SC>, BatchConstraintProof<SC>)>,
    PD::OpeningProof: Into<(StackingProof<SC>, WhirProof<SC>)>,
    TS: FiatShamirTranscript<SC>,
{
    type Proof = Proof<SC>;
    type Error = <PD as ProverDevice<PB, TS>>::Error;
    type ProvingKeyView<'a>
        = &'a DeviceMultiStarkProvingKey<PB>
    where
        Self: 'a;

    type ProvingContext<'a>
        = ProvingContext<PB>
    where
        Self: 'a;

    /// Specialized prove for InteractiveAirs.
    /// Handles trace generation of the permutation traces.
    /// Assumes the main traces have been generated and committed already.
    ///
    /// The [DeviceMultiStarkProvingKey] should already be filtered to only include the relevant
    /// AIR's proving keys.
    #[instrument(
        name = "stark_prove_excluding_trace",
        level = "info",
        skip_all,
        fields(phase = "prover")
    )]
    fn prove<'a>(
        &'a mut self,
        mpk: &'a DeviceMultiStarkProvingKey<PB>,
        unsorted_ctx: ProvingContext<PB>,
    ) -> Result<Self::Proof, Self::Error> {
        let transcript = &mut self.transcript;
        transcript.observe_commit(mpk.vk_pre_hash);

        let ctx = unsorted_ctx.into_sorted();
        // `ctx` should NOT be permuted anymore: the ordering by `trace_idx` is now fixed.

        let num_airs_present = ctx.per_trace.len();
        info!(num_airs_present);

        let _main_commit_span = info_span!("prover.main_trace_commit", phase = "prover").entered();
        let (common_main_commit, common_main_pcs_data) = {
            let traces = ctx
                .common_main_traces()
                .map(|(_, trace)| trace)
                .collect_vec();
            self.device.commit(&traces)?
        };

        let mut trace_vdata: Vec<Option<TraceVData<SC>>> = vec![None; mpk.per_air.len()];
        let mut public_values: Vec<Vec<SC::F>> = vec![Vec::new(); mpk.per_air.len()];

        // Hypercube dimension per trace (present AIR)
        for (air_id, trace_ctx) in &ctx.per_trace {
            let trace_height = trace_ctx.common_main.height();
            let log_height = log2_strict_usize(trace_height);

            trace_vdata[*air_id] = Some(TraceVData::<SC> {
                log_height,
                cached_commitments: trace_ctx
                    .cached_mains
                    .iter()
                    .map(|cd| cd.commitment)
                    .collect(),
            });
            public_values[*air_id] = trace_ctx.public_values.clone();
        }
        #[cfg(feature = "metrics")]
        trace_metrics::<SC, _>(mpk, &trace_vdata).emit();

        // Only observe commits for present AIRs.
        // Commitments order:
        // - 1 commitment of all common main traces
        // - merged preprocessed commitment, once, if the key uses merged mode
        // - for each air:
        //   - preprocessed commit if present (per-air mode only)
        //   - for each cached main trace
        //     - 1 commitment
        // In merged mode every air observes its log_height (heights are additionally
        // bound via the vk pre-hash: hypercube_dim is checked against log_height).
        transcript.observe_commit(common_main_commit);
        drop(_main_commit_span);

        let merged_prep = mpk.merged_preprocessed.is_some();
        if let Some((merged_commit, _)) = &mpk.merged_preprocessed {
            transcript.observe_commit(*merged_commit);
        }

        for (trace_vdata, pvs, pk) in izip!(&trace_vdata, &public_values, &mpk.per_air) {
            if !pk.vk.is_required {
                transcript.observe(SC::F::from_bool(trace_vdata.is_some()));
            }
            if let Some(trace_vdata) = trace_vdata {
                match &pk.preprocessed_data {
                    Some(cd) if !merged_prep => transcript.observe_commit(cd.commitment),
                    _ => transcript.observe(SC::F::from_usize(trace_vdata.log_height)),
                }
                for commit in &trace_vdata.cached_commitments {
                    transcript.observe_commit(*commit);
                }
            }
            for pv in pvs {
                transcript.observe(*pv);
            }
        }

        let (constraints_proof, r) = self.device.prove_rap_constraints(transcript, mpk, &ctx)?;

        let opening_proof =
            self.device
                .prove_openings(transcript, mpk, ctx, common_main_pcs_data, r.into())?;

        let (gkr_proof, batch_constraint_proof) = constraints_proof.into();
        let (stacking_proof, whir_proof) = opening_proof.into();

        Ok(Proof::<SC> {
            public_values,
            trace_vdata,
            common_main_commit,
            gkr_proof,
            batch_constraint_proof,
            stacking_proof,
            whir_proof,
        })
    }
}
