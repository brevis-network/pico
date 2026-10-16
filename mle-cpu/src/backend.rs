//! Row-major [ProverBackend] implementation.

use std::marker::PhantomData;

use p3_matrix::dense::RowMajorMatrix;
use pico_mle_core::{
    prover::{evaluator::InteractionEvalPlan, ProverBackend},
    StarkProtocolConfig,
};

use crate::pcs_data::CpuStackedPcsData;

/// Row-major CPU prover backend.
///
/// Uses `RowMajorMatrix<SC::F>` as the matrix type for better cache locality
/// during constraint evaluation.
#[derive(Clone, Copy)]
pub struct CpuBackend<SC: StarkProtocolConfig>(PhantomData<SC>);

impl<SC: StarkProtocolConfig> CpuBackend<SC> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<SC: StarkProtocolConfig> Default for CpuBackend<SC> {
    fn default() -> Self {
        Self::new()
    }
}

impl<SC: StarkProtocolConfig> ProverBackend for CpuBackend<SC> {
    const CHALLENGE_EXT_DEGREE: u8 = SC::D_EF as u8;

    type Val = SC::F;
    type Challenge = SC::EF;
    type Commitment = SC::Digest;
    type Matrix = RowMajorMatrix<SC::F>;
    type OtherAirData = InteractionEvalPlan<SC::F>;
    type PcsData = CpuStackedPcsData<SC::F, SC::Digest>;
}

#[cfg(test)]
mod tests {
    use p3_field::{ExtensionField, TwoAdicField};
    use pico_mle_core::{
        prover::{HostProverError, ProverDevice},
        FiatShamirTranscript, StarkProtocolConfig,
    };

    use crate::{CpuBackend, CpuDevice};

    /// Compile-time check that this device keeps `HostProverError` as its `ProverDevice::Error`.
    /// Never called; fails to compile if `type Error` is repointed elsewhere.
    #[allow(dead_code)]
    fn cpu_device_uses_host_prover_error<SC, TS>(
        cpu_err: <CpuDevice<SC> as ProverDevice<CpuBackend<SC>, TS>>::Error,
    ) -> HostProverError
    where
        SC: StarkProtocolConfig,
        SC::F: Ord,
        SC::EF: TwoAdicField + ExtensionField<SC::F> + Ord,
        TS: FiatShamirTranscript<SC>,
    {
        cpu_err
    }
}
