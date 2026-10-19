//! The KoalaBear-Poseidon2 reference engine.
//!
//! `config::koala_bear_poseidon2` defines the protocol config and field parameters; this module
//! binds them to a device. Engine wiring lives here rather than in `config/` so that the base
//! configuration layer stays free of `prover` edges.

use std::marker::PhantomData;

use crate::{
    config::koala_bear_poseidon2::{
        default_koalabear_poseidon2_16, DuplexSponge, KoalaBearPoseidon2Config, Perm,
    },
    prover::{Coordinator, ReferenceColMajorBackend, ReferenceDevice},
    FiatShamirTranscript, StarkEngine, SystemParams,
};

type SC = KoalaBearPoseidon2Config;

/// [`StarkEngine`] over the column-major reference device.
pub struct KoalaBearPoseidon2RefEngine<TS = DuplexSponge> {
    device: ReferenceDevice<SC>,
    _transcript: PhantomData<TS>,
}

impl<TS> StarkEngine for KoalaBearPoseidon2RefEngine<TS>
where
    TS: FiatShamirTranscript<SC> + From<Perm>,
{
    type SC = SC;
    type PB = ReferenceColMajorBackend<SC>;
    type PD = ReferenceDevice<SC>;
    type TS = TS;

    fn new(params: SystemParams) -> Self {
        let config = KoalaBearPoseidon2Config::default_from_params(params);
        Self {
            device: ReferenceDevice::new(config),
            _transcript: PhantomData,
        }
    }

    fn config(&self) -> &SC {
        self.device.config()
    }

    fn device(&self) -> &Self::PD {
        &self.device
    }

    fn initial_transcript(&self) -> Self::TS {
        TS::from(default_koalabear_poseidon2_16())
    }

    fn prover_from_transcript(
        &self,
        transcript: TS,
    ) -> Coordinator<Self::SC, Self::PB, Self::PD, Self::TS> {
        Coordinator::new(self.device.clone(), transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::riscv_params_with_100_bits_security, StarkProtocolConfig};

    /// A production KoalaBear `SystemParams` value initializes the reference engine, and the params
    /// survive the round-trip through it.
    #[test]
    fn kb_ref_engine_initializes_from_app_params() {
        let params = riscv_params_with_100_bits_security(20);

        let engine = KoalaBearPoseidon2RefEngine::<DuplexSponge>::new(params.clone());
        assert_eq!(engine.config().params(), &params);
        // Transcript construction from the default permutation succeeds.
        let _transcript = engine.initial_transcript();
    }
}
