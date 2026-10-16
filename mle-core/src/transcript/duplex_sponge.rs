use p3_challenger::CanObserve;
use p3_field::PrimeField;
use p3_symmetric::CryptographicPermutation;

use crate::{FiatShamirTranscript, StarkProtocolConfig, TranscriptHistory, TranscriptLog};

/// Permutation-based duplex sponge in overwrite mode.
///
/// "Duplex" refers to being able to alternately absorb (observe) and squeeze
/// (sample), rather than a single absorb phase followed by a single squeeze
/// phase.
///
/// This variant operates in *overwrite mode*, meaning new inputs overwrite
/// state elements directly (instead of, e.g., being added in).
#[derive(Clone, Debug)]
pub struct DuplexSponge<F, P, const WIDTH: usize, const RATE: usize> {
    perm: P,
    /// Poseidon2 state
    state: [F; WIDTH],
    /// Invariant to be preserved: 0 <= absorb_idx < RATE
    absorb_idx: usize,
    /// Invariant to be preserved: 0 <= sample_idx <= RATE
    sample_idx: usize,
    /// True iff last sample/observe triggered a permutation
    last_op_perm: bool,
}

impl<F: Default + Copy, P, const WIDTH: usize, const RATE: usize> From<P>
    for DuplexSponge<F, P, WIDTH, RATE>
{
    fn from(perm: P) -> Self {
        Self {
            perm,
            state: [F::default(); WIDTH],
            absorb_idx: 0,
            sample_idx: 0,
            last_op_perm: false,
        }
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> DuplexSponge<F, P, WIDTH, RATE> {
    pub fn state(&self) -> &[F; WIDTH] {
        &self.state
    }

    pub fn absorb_idx(&self) -> usize {
        self.absorb_idx
    }

    pub fn sample_idx(&self) -> usize {
        self.sample_idx
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> DuplexSponge<F, P, WIDTH, RATE>
where
    F: Copy,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    /// Absorb a single value (overwrite mode).
    pub fn absorb(&mut self, value: F) {
        self.state[self.absorb_idx] = value;
        self.absorb_idx += 1;
        self.last_op_perm = self.absorb_idx == RATE;
        if self.last_op_perm {
            self.perm.permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = RATE;
        }
    }

    /// Squeeze a single value. Permutes if there are pending absorbs.
    pub fn squeeze(&mut self) -> F {
        self.last_op_perm = self.absorb_idx != 0 || self.sample_idx == 0;
        if self.last_op_perm {
            self.perm.permute_mut(&mut self.state);
            self.absorb_idx = 0;
            self.sample_idx = RATE;
        }
        self.sample_idx -= 1;
        self.state[self.sample_idx]
    }
}

// This implementation **must** be equivalent to Plonky3's `DuplexChallenger`.
impl<SC, F, P, const WIDTH: usize, const RATE: usize> FiatShamirTranscript<SC>
    for DuplexSponge<F, P, WIDTH, RATE>
where
    F: PrimeField,
    SC: StarkProtocolConfig<Digest = [F; RATE], F = F>,
    P: CryptographicPermutation<[F; WIDTH]> + Send + Sync,
{
    fn observe(&mut self, value: F) {
        self.absorb(value);
    }

    fn sample(&mut self) -> F {
        self.squeeze()
    }

    fn observe_commit(&mut self, digest: [F; RATE]) {
        CanObserve::observe(self, digest);
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> CanObserve<F> for DuplexSponge<F, P, WIDTH, RATE>
where
    F: Copy,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    fn observe(&mut self, value: F) {
        self.absorb(value);
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize, const N: usize> CanObserve<[F; N]>
    for DuplexSponge<F, P, WIDTH, RATE>
where
    F: Copy,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    fn observe(&mut self, values: [F; N]) {
        for x in values {
            self.absorb(x);
        }
    }
}

#[derive(Clone)]
pub struct DuplexSpongeRecorder<F, P, const WIDTH: usize, const RATE: usize> {
    pub inner: DuplexSponge<F, P, WIDTH, RATE>,
    pub log: TranscriptLog<F, [F; WIDTH]>,
}

impl<F: Default + Copy, P, const WIDTH: usize, const RATE: usize> From<P>
    for DuplexSpongeRecorder<F, P, WIDTH, RATE>
{
    fn from(perm: P) -> Self {
        let inner = DuplexSponge::from(perm);
        let mut log = TranscriptLog::default();
        log.push_perm_result([F::default(); WIDTH]);
        Self { inner, log }
    }
}

impl<SC, F, P, const WIDTH: usize, const RATE: usize> FiatShamirTranscript<SC>
    for DuplexSpongeRecorder<F, P, WIDTH, RATE>
where
    F: PrimeField,
    SC: StarkProtocolConfig<Digest = [F; RATE], F = F>,
    P: CryptographicPermutation<[F; WIDTH]> + Send + Sync,
{
    fn observe(&mut self, x: F) {
        CanObserve::observe(&mut self.inner, x);
        self.log.push_observe(x);
        if self.inner.last_op_perm {
            self.log.push_perm_result(self.inner.state);
        }
    }

    fn sample(&mut self) -> F {
        let x = FiatShamirTranscript::<SC>::sample(&mut self.inner);
        self.log.push_sample(x);
        if self.inner.last_op_perm {
            self.log.push_perm_result(self.inner.state);
        }
        x
    }

    fn observe_commit(&mut self, digest: [F; RATE]) {
        for x in digest {
            FiatShamirTranscript::<SC>::observe(self, x);
        }
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> TranscriptHistory
    for DuplexSpongeRecorder<F, P, WIDTH, RATE>
{
    type F = F;
    type State = [F; WIDTH];

    fn len(&self) -> usize {
        self.log.len()
    }

    fn into_log(self) -> TranscriptLog<F, [F; WIDTH]> {
        self.log
    }
}

/// [DuplexSpongeRecorder] that checks the live transcript logs against a provided transcript log.
/// For testing usage.
#[derive(Clone)]
pub struct DuplexSpongeValidator<F, P, const WIDTH: usize, const RATE: usize> {
    pub inner: DuplexSpongeRecorder<F, P, WIDTH, RATE>,
    pub idx: usize,
    log: TranscriptLog<F, [F; WIDTH]>,
}

impl<F: Default + Copy, P, const WIDTH: usize, const RATE: usize>
    DuplexSpongeValidator<F, P, WIDTH, RATE>
{
    pub fn new(perm: P, log: TranscriptLog<F, [F; WIDTH]>) -> Self {
        debug_assert_eq!(log.len(), log.samples().len());
        Self {
            inner: perm.into(),
            idx: 0,
            log,
        }
    }
}

impl<SC, F, P, const WIDTH: usize, const RATE: usize> FiatShamirTranscript<SC>
    for DuplexSpongeValidator<F, P, WIDTH, RATE>
where
    F: PrimeField,
    SC: StarkProtocolConfig<Digest = [F; RATE], F = F>,
    P: CryptographicPermutation<[F; WIDTH]> + Send + Sync,
{
    fn observe(&mut self, x: F) {
        debug_assert!(self.idx < self.log.len(), "transcript replay overflow");
        assert!(!self.log.samples()[self.idx]);
        let exp_x = self.log[self.idx];
        assert_eq!(x, exp_x);
        self.idx += 1;
        FiatShamirTranscript::<SC>::observe(&mut self.inner, x);
    }

    fn sample(&mut self) -> F {
        debug_assert!(self.idx < self.log.len(), "transcript replay overflow");
        assert!(self.log.samples()[self.idx]);
        let x = FiatShamirTranscript::<SC>::sample(&mut self.inner);
        let exp_x = self.log[self.idx];
        self.idx += 1;
        assert_eq!(x, exp_x);
        x
    }

    fn observe_commit(&mut self, digest: [F; RATE]) {
        for x in digest {
            FiatShamirTranscript::<SC>::observe(self, x);
        }
    }
}

impl<F, P, const WIDTH: usize, const RATE: usize> TranscriptHistory
    for DuplexSpongeValidator<F, P, WIDTH, RATE>
{
    type F = F;
    type State = [F; WIDTH];

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn into_log(self) -> TranscriptLog<F, [F; WIDTH]> {
        debug_assert_eq!(self.inner.len(), self.log.len());
        debug_assert_eq!(
            self.inner.len(),
            self.idx,
            "transcript replay ended with {} of {} entries consumed",
            self.idx,
            self.inner.len()
        );
        debug_assert_eq!(
            self.log.len(),
            self.idx,
            "transcript replay ended with {} of {} entries consumed",
            self.idx,
            self.log.len()
        );
        self.inner.into_log()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{default_koalabear_poseidon2_16, KoalaBearPoseidon2Config},
        p3_challenger::{CanObserve, CanSample, DuplexChallenger},
    };

    const WIDTH: usize = 16;
    const RATE: usize = 8;

    type SC = KoalaBearPoseidon2Config;
    type Sponge = DuplexSponge<KoalaBear, Poseidon2KoalaBear<WIDTH>, WIDTH, RATE>;
    type RefChallenger = DuplexChallenger<KoalaBear, Poseidon2KoalaBear<WIDTH>, WIDTH, RATE>;

    fn kb(x: u32) -> KoalaBear {
        KoalaBear::from_u32(x)
    }

    /// The duplex sponge must be byte-exact with Plonky3's `DuplexChallenger` (the reference it
    /// claims equivalence to) under an arbitrary interleaving of observes and samples that crosses
    /// rate boundaries in both directions.
    #[test]
    fn duplex_sponge_matches_p3_duplex_challenger() {
        let perm = default_koalabear_poseidon2_16();
        let mut sponge: Sponge = perm.clone().into();
        let mut reference = RefChallenger::new(perm);

        for round in 0..64u32 {
            // Observe 1..=5 values, then sample 1..=3 — deliberately not aligned to RATE=8 so
            // the absorb/permute/squeeze boundaries get exercised at every phase.
            let n_obs = (round % 5) + 1;
            for j in 0..n_obs {
                let v = kb(round.wrapping_mul(7).wrapping_add(j).wrapping_add(1));
                FiatShamirTranscript::<SC>::observe(&mut sponge, v);
                CanObserve::observe(&mut reference, v);
            }
            let n_samp = (round % 3) + 1;
            for _ in 0..n_samp {
                let got = FiatShamirTranscript::<SC>::sample(&mut sponge);
                let want: KoalaBear = CanSample::sample(&mut reference);
                assert_eq!(got, want, "sample mismatch at round {round}");
            }
        }
    }

    /// `observe_commit` (digest absorption) must also stay byte-exact with the reference, which
    /// observes the digest elements one by one.
    #[test]
    fn observe_commit_matches_p3_observe_slice() {
        let perm = default_koalabear_poseidon2_16();
        let mut sponge: Sponge = perm.clone().into();
        let mut reference = RefChallenger::new(perm);

        let digest: [KoalaBear; RATE] = core::array::from_fn(|i| kb(i as u32 + 100));
        FiatShamirTranscript::<SC>::observe_commit(&mut sponge, digest);
        for x in digest {
            CanObserve::observe(&mut reference, x);
        }
        let want: KoalaBear = CanSample::sample(&mut reference);
        assert_eq!(FiatShamirTranscript::<SC>::sample(&mut sponge), want);
    }

    /// A fixed observe→sample sequence is reproducible: same inputs ⇒ identical sampled outputs.
    #[test]
    fn observe_sample_sequence_is_deterministic() {
        let run = || {
            let mut t: Sponge = default_koalabear_poseidon2_16().into();
            let mut out = Vec::new();
            for i in 0..32u32 {
                FiatShamirTranscript::<SC>::observe(&mut t, kb(i + 1));
                if i % 2 == 0 {
                    out.push(FiatShamirTranscript::<SC>::sample(&mut t));
                }
            }
            out
        };
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    /// `grind` must find a witness that `check_witness` accepts against the same transcript state.
    #[test]
    fn grind_produces_valid_witness() {
        let bits = 8;
        let mut sponge: Sponge = default_koalabear_poseidon2_16().into();
        FiatShamirTranscript::<SC>::observe(&mut sponge, kb(42));

        let mut verifier = sponge.clone();
        let witness = FiatShamirTranscript::<SC>::grind(&mut sponge, bits);
        assert!(FiatShamirTranscript::<SC>::check_witness(
            &mut verifier,
            bits,
            witness
        ));
    }

    /// `sample_bits(b)` returns a value in `[0, 2^b)`.
    #[test]
    fn sample_bits_stays_in_range() {
        let mut t: Sponge = default_koalabear_poseidon2_16().into();
        FiatShamirTranscript::<SC>::observe(&mut t, kb(7));
        for bits in 1..=16usize {
            let s = FiatShamirTranscript::<SC>::sample_bits(&mut t, bits);
            assert!(s < (1u64 << bits), "sample_bits({bits}) = {s} out of range");
        }
    }

    /// A log recorded by `DuplexSpongeRecorder` replays cleanly through `DuplexSpongeValidator`,
    /// and the recorder's sampled values match a plain sponge driven identically.
    #[test]
    fn recorder_log_replays_through_validator() {
        let perm = default_koalabear_poseidon2_16();
        let mut recorder: DuplexSpongeRecorder<_, _, WIDTH, RATE> = perm.clone().into();
        let mut plain: Sponge = perm.clone().into();

        for i in 0..24u32 {
            FiatShamirTranscript::<SC>::observe(&mut recorder, kb(i + 1));
            FiatShamirTranscript::<SC>::observe(&mut plain, kb(i + 1));
            if i % 3 == 0 {
                let r = FiatShamirTranscript::<SC>::sample(&mut recorder);
                let p = FiatShamirTranscript::<SC>::sample(&mut plain);
                assert_eq!(r, p, "recorder diverged from plain sponge at {i}");
            }
        }
        let log = recorder.into_log();

        // Replay the recorded values/flags through the validator; it asserts (in debug) that every
        // value and observe/sample flag matches and that the whole log is consumed.
        let mut validator = DuplexSpongeValidator::new(perm, log.clone());
        let values = log.values().to_vec();
        let flags = log.samples().to_vec();
        for (v, is_sample) in values.iter().zip(flags.iter()) {
            if *is_sample {
                let got = FiatShamirTranscript::<SC>::sample(&mut validator);
                assert_eq!(got, *v);
            } else {
                FiatShamirTranscript::<SC>::observe(&mut validator, *v);
            }
        }
        let _ = validator.into_log();
    }
}
