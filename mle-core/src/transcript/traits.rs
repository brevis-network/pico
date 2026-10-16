use std::ops::Deref;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField, PrimeField64};
use p3_maybe_rayon::prelude::*;
use tracing::instrument;

use crate::StarkProtocolConfig;

/// Unified trait describing the interface for the Fiat-Shamir transcript needed by the
/// MLE proof system.
pub trait FiatShamirTranscript<SC>: Clone + Send + Sync
where
    SC: StarkProtocolConfig,
{
    fn observe(&mut self, value: SC::F);
    fn sample(&mut self) -> SC::F;

    /// Implementations should pass through to [Self::observe], but no default implementation is
    /// provided since an explicit conversion from `Digest` to array of `F` is required.
    fn observe_commit(&mut self, digest: SC::Digest);

    fn observe_ext(&mut self, value: SC::EF) {
        // for i in 0..D
        for &base_val in value.as_basis_coefficients_slice() {
            self.observe(base_val);
        }
    }

    fn sample_ext(&mut self) -> SC::EF {
        SC::EF::from_basis_coefficients_fn(|_| self.sample())
    }

    fn sample_bits(&mut self, bits: usize) -> u64 {
        assert!(bits < (u32::BITS as usize));
        assert!((1 << bits) < SC::F::ORDER_U64);
        let rand_f: SC::F = self.sample();
        let rand_u64 = rand_f.as_canonical_u64();
        rand_u64 & ((1 << bits) - 1)
    }

    #[must_use]
    fn check_witness(&mut self, bits: usize, witness: SC::F) -> bool {
        if bits == 0 {
            return true;
        }
        self.observe(witness);
        self.sample_bits(bits) == 0
    }

    #[instrument(name = "grind_pow", skip_all)]
    fn grind(&mut self, bits: usize) -> SC::F {
        assert!(bits < (u32::BITS as usize));
        assert!((1 << bits) < SC::F::ORDER_U64);
        // Trivial case: 0 bits mean no PoW is required and any witness is valid.
        if bits == 0 {
            return SC::F::ZERO;
        }

        let witness = (0..SC::F::ORDER_U64)
            .into_par_iter()
            .map(SC::F::from_u64)
            .find_any(|witness| self.clone().check_witness(bits, *witness))
            .expect("failed to find PoW witness");
        assert!(self.check_witness(bits, witness));
        witness
    }
}

pub trait TranscriptHistory {
    type F;
    type State;

    fn len(&self) -> usize;
    fn into_log(self) -> TranscriptLog<Self::F, Self::State>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Log of transcript history
#[derive(Clone, Debug)]
pub struct TranscriptLog<F, State> {
    /// Every sampled or observed value F
    values: Vec<F>,
    /// True iff values[tidx] was a sampled value
    is_sample: Vec<bool>,
    /// Sponge state after every permutation; note that not all implementations of
    /// TranscriptHistory will define this
    perm_results: Vec<State>,
}

impl<F, State> Default for TranscriptLog<F, State> {
    fn default() -> Self {
        Self {
            values: Vec::new(),
            is_sample: Vec::new(),
            perm_results: Vec::new(),
        }
    }
}

impl<F: Clone, State> TranscriptLog<F, State> {
    pub fn new(values: Vec<F>, is_sample: Vec<bool>) -> Self {
        debug_assert_eq!(values.len(), is_sample.len());
        Self {
            values,
            is_sample,
            perm_results: vec![],
        }
    }

    pub fn values(&self) -> &[F] {
        &self.values
    }

    pub fn values_mut(&mut self) -> &mut [F] {
        &mut self.values
    }

    pub fn samples(&self) -> &[bool] {
        &self.is_sample
    }

    pub fn samples_mut(&mut self) -> &mut [bool] {
        &mut self.is_sample
    }

    pub fn push_observe(&mut self, value: F) {
        self.values.push(value);
        self.is_sample.push(false);
    }

    pub fn push_sample(&mut self, value: F) {
        self.values.push(value);
        self.is_sample.push(true);
    }

    pub fn push_perm_result(&mut self, state: State) {
        self.perm_results.push(state);
    }

    pub fn extend_observe(&mut self, values: &[F]) {
        self.values.extend_from_slice(values);
        self.is_sample
            .extend(core::iter::repeat_n(false, values.len()));
    }

    pub fn extend_sample(&mut self, values: &[F]) {
        self.values.extend_from_slice(values);
        self.is_sample
            .extend(core::iter::repeat_n(true, values.len()));
    }

    pub fn extend_with_flags(&mut self, values: &[F], sample_flags: &[bool]) {
        debug_assert_eq!(values.len(), sample_flags.len());
        self.values.extend_from_slice(values);
        self.is_sample.extend(sample_flags.iter().copied());
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn into_parts(self) -> (Vec<F>, Vec<bool>) {
        (self.values, self.is_sample)
    }

    pub fn perm_results(&self) -> &Vec<State> {
        &self.perm_results
    }
}

impl<F, State> Deref for TranscriptLog<F, State> {
    type Target = [F];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

/// Read-only transcript that replays a recorded log.
#[derive(Clone, Debug)]
pub struct ReadOnlyTranscript<'a, F, State> {
    log: &'a TranscriptLog<F, State>,
    position: usize,
}

impl<'a, F, State> ReadOnlyTranscript<'a, F, State> {
    pub fn new(log: &'a TranscriptLog<F, State>, start_idx: usize) -> Self {
        debug_assert!(start_idx <= log.len(), "start index out of bounds");
        Self {
            log,
            position: start_idx,
        }
    }
}

impl<SC, F, const WIDTH: usize, const RATE: usize> FiatShamirTranscript<SC>
    for ReadOnlyTranscript<'_, F, [F; WIDTH]>
where
    F: PrimeField,
    SC: StarkProtocolConfig<F = F, Digest = [F; RATE]>,
{
    #[inline]
    fn observe(&mut self, value: F) {
        debug_assert!(
            !self.log.samples()[self.position],
            "expected observe at {}",
            self.position
        );
        debug_assert_eq!(
            self.log.values()[self.position],
            value,
            "value mismatch at {}",
            self.position
        );
        self.position += 1;
    }

    #[inline]
    fn sample(&mut self) -> F {
        debug_assert!(
            self.log.samples()[self.position],
            "expected sample at {}",
            self.position
        );
        let value = self.log.values()[self.position];
        self.position += 1;
        value
    }

    fn observe_commit(&mut self, digest: [F; RATE]) {
        for x in digest {
            FiatShamirTranscript::<SC>::observe(self, x);
        }
    }
}

impl<F, State> TranscriptHistory for ReadOnlyTranscript<'_, F, State>
where
    F: Clone,
    State: Clone,
{
    type F = F;
    type State = State;

    fn len(&self) -> usize {
        self.position
    }

    fn into_log(self) -> TranscriptLog<F, State> {
        self.log.clone()
    }
}
