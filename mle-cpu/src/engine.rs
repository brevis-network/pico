//! The KoalaBear-Poseidon2 engine over the row-major CPU device.
//!
//! `WIDTH`, `RATE` and `Perm` are re-used from [`pico_mle_core::config::koala_bear_poseidon2`]
//! rather than redeclared: divergence there would be a soundness bug.

use std::marker::PhantomData;

use pico_mle_core::{
    config::koala_bear_poseidon2::{
        default_koalabear_poseidon2_16, KoalaBearPoseidon2Config, Perm, RATE, WIDTH,
    },
    p3_challenger::{CanObserve, CanSample, DuplexChallenger},
    p3_koala_bear::{KoalaBear, Poseidon2KoalaBear},
    prover::Coordinator,
    FiatShamirTranscript, StarkEngine, SystemParams,
};

use crate::{CpuBackend, CpuDevice};

type SC = KoalaBearPoseidon2Config;

#[derive(Clone, Debug)]
pub struct KbCpuTranscript {
    inner: DuplexChallenger<KoalaBear, Poseidon2KoalaBear<WIDTH>, WIDTH, RATE>,
}

impl From<Perm> for KbCpuTranscript {
    fn from(perm: Perm) -> Self {
        Self {
            inner: DuplexChallenger::new(perm),
        }
    }
}

impl FiatShamirTranscript<KoalaBearPoseidon2Config> for KbCpuTranscript {
    #[inline]
    fn observe(&mut self, value: KoalaBear) {
        CanObserve::observe(&mut self.inner, value);
    }

    #[inline]
    fn sample(&mut self) -> KoalaBear {
        CanSample::sample(&mut self.inner)
    }

    fn observe_commit(&mut self, digest: [KoalaBear; RATE]) {
        for x in digest {
            CanObserve::observe(&mut self.inner, x);
        }
    }
}

/// [`StarkEngine`] over the row-major CPU device. This is the engine the RISCV proving path uses.
pub struct KoalaBearPoseidon2CpuEngine<TS = KbCpuTranscript> {
    device: CpuDevice<SC>,
    _transcript: PhantomData<TS>,
}

impl<TS> StarkEngine for KoalaBearPoseidon2CpuEngine<TS>
where
    TS: FiatShamirTranscript<SC> + From<Poseidon2KoalaBear<WIDTH>>,
{
    type SC = SC;
    type PB = CpuBackend<SC>;
    type PD = CpuDevice<SC>;
    type TS = TS;

    fn new(params: SystemParams) -> Self {
        let config = KoalaBearPoseidon2Config::default_from_params(params);
        Self {
            device: CpuDevice::new(config),
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
    use pico_mle_core::p3_field::PrimeCharacteristicRing;

    use super::*;

    /// Zero PoW is a protocol no-op: prover grinding and verifier witness checking must leave the
    /// Fiat--Shamir transcript in the same state before the next challenge is sampled.
    #[test]
    fn zero_bit_grind_does_not_advance_transcript() {
        let permutation = default_koalabear_poseidon2_16();
        let mut ground = KbCpuTranscript::from(permutation.clone());
        let mut untouched = KbCpuTranscript::from(permutation);

        ground.observe(KoalaBear::ONE);
        untouched.observe(KoalaBear::ONE);
        assert_eq!(
            FiatShamirTranscript::<SC>::grind(&mut ground, 0),
            KoalaBear::ZERO
        );
        assert_eq!(ground.sample(), untouched.sample());
    }
}
