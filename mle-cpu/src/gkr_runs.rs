//! The GKR fractional sumcheck over an input stored as runs.
//!
//! A trace ends in rows that repeat its last row, and on all of them but the last every
//! interaction evaluates to the same leaf. A table of `2^22` rows with a few thousand real ones
//! is almost entirely one leaf per interaction, and the rest of the stacked input, past its last
//! trace, is one leaf too. [`Runs`] stores a vector as stretches of values kept one by one and
//! stretches of one repeated value.
//!
//! Everything the dense prover (`pico_mle_core`'s `fractional_sumcheck`) does to its vectors goes
//! by adjacent pairs: a tree node from its two children, a folded entry from two entries, a
//! round's sum from the pairs' terms. The pairs inside a repeated stretch hold the same values:
//! its tree nodes and its folded entries are computed once, and its terms in a round differ only
//! in their `eq` factor, which is summed over the stretch. The messages are the dense prover's,
//! field element for field element; [`fractional_sumcheck_over_runs`] is that prover on this
//! storage.

use p3_field::{Field, PrimeCharacteristicRing};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use pico_mle_core::{
    poly::evals_eq_hypercube_par,
    proof::GkrLayerClaims,
    prover::{
        error::LogupZerocheckError,
        fractional_sumcheck_gkr::{Frac, FracSumcheckProof},
    },
    FiatShamirTranscript, StarkProtocolConfig,
};
use tracing::instrument;

/// A stretch of fewer pairs than this is handled on the calling thread; the sums of a round take
/// this many pairs per parallel task.
const PAIRS_PER_TASK: usize = 1 << 10;

/// A stretch shorter than this is written into the stored run before it, when there is one, and
/// is not kept as a run of its own: the layers and folded vectors of a tree halve as they go, and
/// their runs with them, and a vector cut into many short runs costs more to walk than it saves.
const SHORT_RUN: usize = 1 << 6;

/// A stretch of a [`Runs`] vector.
#[derive(Clone, Debug)]
enum Run<T> {
    /// Values kept one by one.
    Stored(Vec<T>),
    /// `len` copies of `value`.
    Repeated { value: T, len: usize },
}

/// A vector stored as stretches of values kept one by one and stretches of one repeated value.
#[derive(Clone, Debug)]
pub struct Runs<T> {
    /// In order, none of them empty.
    runs: Vec<Run<T>>,
    len: usize,
}

impl<T> Default for Runs<T> {
    fn default() -> Self {
        Self {
            runs: Vec::new(),
            len: 0,
        }
    }
}

/// The pairs `(v[2y], v[2y + 1])` of a [`Runs`] vector `v` for a stretch of `y`.
enum PairStretch<'a, T> {
    /// The pairs of this slice, whose length is even.
    Stored(&'a [T]),
    /// `count` times the pair `(value, value)`.
    Repeated { value: T, count: usize },
    /// One pair whose halves lie in two runs.
    Split(T, T),
}

impl<T: Copy + Send + Sync> Runs<T> {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends `values`.
    pub fn push_stored(&mut self, values: Vec<T>) {
        if values.is_empty() {
            return;
        }
        self.len += values.len();
        match self.runs.last_mut() {
            Some(Run::Stored(last)) if values.len() < SHORT_RUN => last.extend(values),
            _ => self.runs.push(Run::Stored(values)),
        }
    }

    /// Appends `len` copies of `value`.
    pub fn push_repeated(&mut self, value: T, len: usize) {
        if len == 0 {
            return;
        }
        self.len += len;
        match self.runs.last_mut() {
            Some(Run::Stored(last)) if len < SHORT_RUN => last.resize(last.len() + len, value),
            _ => self.runs.push(Run::Repeated { value, len }),
        }
    }

    /// How many values are kept one by one, and how many stretches are one repeated value.
    #[cfg(test)]
    pub fn stored_and_repeated(&self) -> (usize, usize) {
        let stored = |run: &Run<T>| match run {
            Run::Stored(values) => values.len(),
            Run::Repeated { .. } => 0,
        };
        let repeated = |run: &&Run<T>| matches!(run, Run::Repeated { .. });
        (
            self.runs.iter().map(stored).sum(),
            self.runs.iter().filter(repeated).count(),
        )
    }

    /// The vector written out.
    #[cfg(test)]
    pub fn to_vec(&self) -> Vec<T> {
        let mut out = Vec::with_capacity(self.len);
        for run in &self.runs {
            match run {
                Run::Stored(values) => out.extend_from_slice(values),
                Run::Repeated { value, len } => out.resize(out.len() + len, *value),
            }
        }
        out
    }

    /// The only value of a vector of length one.
    fn only(&self) -> T {
        assert_eq!(self.len, 1, "a vector of one value");
        match &self.runs[0] {
            Run::Stored(values) => values[0],
            Run::Repeated { value, .. } => *value,
        }
    }

    /// The adjacent pairs, in order, of the vector, whose length is even.
    fn pair_stretches(&self) -> Vec<PairStretch<'_, T>> {
        assert_eq!(self.len % 2, 0, "pairs of a vector of even length");
        let mut stretches = Vec::with_capacity(2 * self.runs.len());
        // The first half of a pair whose second half is in the next run.
        let mut unpaired = None;
        for run in &self.runs {
            match run {
                Run::Stored(values) => {
                    let mut values = values.as_slice();
                    if let Some(first) = unpaired.take() {
                        stretches.push(PairStretch::Split(first, values[0]));
                        values = &values[1..];
                    }
                    let even = values.len() & !1;
                    if even != 0 {
                        stretches.push(PairStretch::Stored(&values[..even]));
                    }
                    unpaired = values.get(even).copied();
                }
                Run::Repeated { value, len } => {
                    let mut len = *len;
                    if let Some(first) = unpaired.take() {
                        stretches.push(PairStretch::Split(first, *value));
                        len -= 1;
                    }
                    if len >= 2 {
                        stretches.push(PairStretch::Repeated {
                            value: *value,
                            count: len / 2,
                        });
                    }
                    unpaired = (len % 2 == 1).then_some(*value);
                }
            }
        }
        debug_assert!(unpaired.is_none());
        stretches
    }

    /// The vector of half the length whose entry `y` is `f(v[2y], v[2y + 1])`.
    fn map_pairs<U: Copy + Send + Sync>(&self, f: impl Fn(T, T) -> U + Sync) -> Runs<U> {
        let mut out = Runs::default();
        for stretch in self.pair_stretches() {
            match stretch {
                PairStretch::Stored(values) => {
                    let pairs = values.as_chunks::<2>().0;
                    out.push_stored(if pairs.len() < PAIRS_PER_TASK {
                        pairs.iter().map(|&[even, odd]| f(even, odd)).collect()
                    } else {
                        pairs.par_iter().map(|&[even, odd]| f(even, odd)).collect()
                    });
                }
                PairStretch::Repeated { value, count } => out.push_repeated(f(value, value), count),
                PairStretch::Split(first, second) => out.push_stored(vec![f(first, second)]),
            }
        }
        out
    }
}

/// What a pair of a layer contributes to its round polynomial at 1, 2 and 3: with `X` the
/// round's variable, `eq(X) * (p0(X) q1(X) + p1(X) q0(X) + lambda q0(X) q1(X))`, every factor the
/// line through its two values. The columns of `pq` are `p0, q0, p1, q1`.
fn pair_terms<EF: Field>(eq: [EF; 2], pq: [[EF; 4]; 2], lambda: EF) -> [EF; 3] {
    core::array::from_fn(|i| {
        let x = EF::from_usize(i + 1);
        let at = |from: EF, to: EF| from + (to - from) * x;
        let [p0, q0, p1, q1] = core::array::from_fn(|column| at(pq[0][column], pq[1][column]));
        at(eq[0], eq[1]) * (p0 * q1 + p1 * q0 + lambda * q0 * q1)
    })
}

fn add_assign<EF: Field, const N: usize>(sum: &mut [EF; N], term: [EF; N]) {
    for (sum, term) in sum.iter_mut().zip(term) {
        *sum += term;
    }
}

/// The sum of `term(i)` over `i` in `0..len`, a task's worth at a time in parallel.
fn sum_of_terms<EF: Field, const N: usize>(
    len: usize,
    term: impl Fn(usize) -> [EF; N] + Sync,
) -> [EF; N] {
    let sum_of = |from: usize, to: usize| {
        let mut sum = [EF::ZERO; N];
        for i in from..to {
            add_assign(&mut sum, term(i));
        }
        sum
    };
    if len < PAIRS_PER_TASK {
        return sum_of(0, len);
    }
    let sums: Vec<[EF; N]> = (0..len.div_ceil(PAIRS_PER_TASK))
        .into_par_iter()
        .map(|task| sum_of(task * PAIRS_PER_TASK, len.min((task + 1) * PAIRS_PER_TASK)))
        .collect();
    let mut sum = [EF::ZERO; N];
    for task in sums {
        add_assign(&mut sum, task);
    }
    sum
}

/// The round polynomial of one sumcheck round at 1, 2 and 3: the sum of [`pair_terms`] over the
/// pairs of `pq` and `eq`, which have the same length.
fn round_poly_evals<EF: Field>(pq: &Runs<[EF; 4]>, eq: &[EF], lambda: EF) -> [EF; 3] {
    debug_assert_eq!(pq.len(), eq.len());
    // The pairs of `eq` not yet used: the first goes with the next pair of `pq`.
    let mut eq_pairs = eq.as_chunks::<2>().0;
    let mut evals = [EF::ZERO; 3];
    for stretch in pq.pair_stretches() {
        let used = match stretch {
            PairStretch::Stored(values) => {
                let pq_pairs = values.as_chunks::<2>().0;
                add_assign(
                    &mut evals,
                    sum_of_terms(pq_pairs.len(), |i| {
                        pair_terms(eq_pairs[i], pq_pairs[i], lambda)
                    }),
                );
                pq_pairs.len()
            }
            // Every factor but `eq` is the same for each pair of the stretch, and constant in
            // `X`, so the stretch's terms sum to that constant times the sum of its `eq` lines.
            PairStretch::Repeated { value, count } => {
                let eq_sum = sum_of_terms(count, |i| eq_pairs[i]);
                add_assign(&mut evals, pair_terms(eq_sum, [value, value], lambda));
                count
            }
            PairStretch::Split(first, second) => {
                add_assign(&mut evals, pair_terms(eq_pairs[0], [first, second], lambda));
                1
            }
        };
        eq_pairs = &eq_pairs[used..];
    }
    evals
}

/// `pico_mle_core`'s `fractional_sumcheck` on leaves stored as runs: the same protocol, the same
/// transcript, the same proof and evaluation point. `leaves` holds a power of two of fractions,
/// two at least, or none.
#[instrument(level = "info", skip_all)]
pub fn fractional_sumcheck_over_runs<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    transcript: &mut TS,
    leaves: &Runs<Frac<SC::EF>>,
    assert_zero: bool,
) -> Result<(FracSumcheckProof<SC>, Vec<SC::EF>), LogupZerocheckError> {
    if leaves.is_empty() {
        return Ok((
            FracSumcheckProof {
                fractional_sum: (SC::EF::ZERO, SC::EF::ONE),
                claims_per_layer: vec![],
                sumcheck_polys: vec![],
            },
            vec![],
        ));
    }
    let total_rounds = log2_strict_usize(leaves.len());
    assert!(total_rounds >= 1, "the tree has a layer below its leaves");

    // The tree above the leaves, each layer the sums of the pairs of the one before it:
    // `above[i]` has `2^(total_rounds - 1 - i)` nodes.
    let mut above: Vec<Runs<Frac<SC::EF>>> = Vec::with_capacity(total_rounds);
    for _ in 0..total_rounds {
        let children = above.last().unwrap_or(leaves);
        let parents = children.map_pairs(|left, right| left + right);
        above.push(parents);
    }
    // The layer of `2^log_nodes` nodes.
    let layer = |log_nodes: usize| {
        if log_nodes == total_rounds {
            leaves
        } else {
            &above[total_rounds - 1 - log_nodes]
        }
    };

    let frac_sum = layer(0).only();
    if assert_zero {
        if frac_sum.p != SC::EF::ZERO {
            return Err(LogupZerocheckError::NonZeroRootSum);
        }
    } else {
        transcript.observe_ext(frac_sum.p);
    }
    transcript.observe_ext(frac_sum.q);

    // The claims on a layer's two halves at the point the round ends on, sent in this order.
    let mut claims_per_layer: Vec<GkrLayerClaims<SC>> = Vec::with_capacity(total_rounds);
    let mut claim = |transcript: &mut TS, [p_xi_0, q_xi_0, p_xi_1, q_xi_1]: [SC::EF; 4]| {
        for value in [p_xi_0, q_xi_0, p_xi_1, q_xi_1] {
            transcript.observe_ext(value);
        }
        claims_per_layer.push(GkrLayerClaims {
            p_xi_0,
            q_xi_0,
            p_xi_1,
            q_xi_1,
        });
    };

    let halves = |left: Frac<SC::EF>, right: Frac<SC::EF>| [left.p, left.q, right.p, right.q];
    // The layer of two nodes is checked by the verifier directly.
    claim(transcript, layer(1).map_pairs(halves).only());
    let mut xi = vec![transcript.sample_ext()];

    // Sumcheck polynomials of the layers of four nodes and more, a layer's rounds in order.
    let mut sumcheck_polys = Vec::with_capacity(total_rounds);
    for round in 1..total_rounds {
        let lambda = transcript.sample_ext();
        // Entry `y` holds nodes `2y` and `2y + 1` of the layer of `2^(round + 1)` nodes.
        let mut pq = layer(round + 1).map_pairs(halves);
        let mut eq = evals_eq_hypercube_par(&xi);
        let mut round_polys = Vec::with_capacity(round);
        let mut rho = Vec::with_capacity(round);
        for _ in 0..round {
            let evals = round_poly_evals(&pq, &eq, lambda);
            for &eval in &evals {
                transcript.observe_ext(eval);
            }
            round_polys.push(evals);

            let r = transcript.sample_ext();
            pq = pq.map_pairs(|from, to| {
                core::array::from_fn(|column| from[column] + (to[column] - from[column]) * r)
            });
            let fold = |&[from, to]: &[SC::EF; 2]| from + (to - from) * r;
            let pairs = eq.as_chunks::<2>().0;
            eq = if pairs.len() < PAIRS_PER_TASK {
                pairs.iter().map(fold).collect()
            } else {
                pairs.par_iter().map(fold).collect()
            };
            rho.push(r);
        }
        claim(transcript, pq.only());
        sumcheck_polys.push(round_polys);

        xi = [vec![transcript.sample_ext()], rho].concat();
    }

    Ok((
        FracSumcheckProof {
            fractional_sum: (frac_sum.p, frac_sum.q),
            claims_per_layer,
            sumcheck_polys,
        },
        xi,
    ))
}

#[cfg(test)]
mod tests {
    use p3_field::BasedVectorSpace;
    use pico_mle_core::{
        config::koala_bear_poseidon2::{
            default_koalabear_poseidon2_16, DuplexSponge, KoalaBearPoseidon2Config as SC, EF, F,
        },
        prover::fractional_sumcheck_gkr::fractional_sumcheck,
    };
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    use super::*;

    fn random_ef(rng: &mut StdRng) -> EF {
        EF::from_basis_coefficients_fn(|_| F::from_u32(rng.random()))
    }

    fn random_frac(rng: &mut StdRng) -> Frac<EF> {
        Frac::new(random_ef(rng), random_ef(rng))
    }

    /// `stretches` as a vector: `(stored, repeated)` is `stored` random fractions, then one random
    /// fraction `repeated` times.
    ///
    /// The runs are held to the same values pushed into a plain vector, so that what the two
    /// provers are compared on is what was meant.
    fn random_leaves(rng: &mut StdRng, stretches: &[(usize, usize)]) -> Runs<Frac<EF>> {
        let mut runs = Runs::default();
        let mut plain = Vec::new();
        for &(stored, repeated) in stretches {
            let stored: Vec<_> = (0..stored).map(|_| random_frac(rng)).collect();
            plain.extend_from_slice(&stored);
            runs.push_stored(stored);
            let value = random_frac(rng);
            plain.resize(plain.len() + repeated, value);
            runs.push_repeated(value, repeated);
        }
        let written = runs.to_vec();
        assert_eq!(written.len(), plain.len());
        for (written, plain) in written.iter().zip(&plain) {
            assert_eq!((written.p, written.q), (plain.p, plain.q));
        }
        runs
    }

    /// The prover over runs and the dense prover on the same vector: the same proof, the same
    /// point, and transcripts left in the same state.
    fn assert_same_as_dense(leaves: &Runs<Frac<EF>>, assert_zero: bool) {
        let fresh = || DuplexSponge::from(default_koalabear_poseidon2_16());
        let (mut over_runs, mut dense) = (fresh(), fresh());
        let ours = fractional_sumcheck_over_runs::<SC, _>(&mut over_runs, leaves, assert_zero);
        let theirs = fractional_sumcheck::<SC, _>(&mut dense, &leaves.to_vec(), assert_zero);
        let ((ours, our_xi), (theirs, their_xi)) = match (ours, theirs) {
            (Ok(ours), Ok(theirs)) => (ours, theirs),
            (Err(ours), Err(theirs)) => {
                assert_eq!(format!("{ours:?}"), format!("{theirs:?}"));
                return;
            }
            (ours, theirs) => panic!(
                "one prover refused the input and the other did not: over runs {}, dense {}",
                ours.is_ok(),
                theirs.is_ok()
            ),
        };
        assert_eq!(ours.fractional_sum, theirs.fractional_sum);
        assert_eq!(ours.sumcheck_polys, theirs.sumcheck_polys);
        assert_eq!(ours.claims_per_layer.len(), theirs.claims_per_layer.len());
        for (ours, theirs) in ours.claims_per_layer.iter().zip(&theirs.claims_per_layer) {
            assert_eq!(
                [ours.p_xi_0, ours.q_xi_0, ours.p_xi_1, ours.q_xi_1],
                [theirs.p_xi_0, theirs.q_xi_0, theirs.p_xi_1, theirs.q_xi_1]
            );
        }
        assert_eq!(our_xi, their_xi);
        assert_eq!(
            FiatShamirTranscript::<SC>::sample_ext(&mut over_runs),
            FiatShamirTranscript::<SC>::sample_ext(&mut dense)
        );
    }

    #[test]
    fn pairs_of_runs_are_the_pairs_of_the_vector() {
        let mut rng = StdRng::seed_from_u64(1);
        // Odd stretches, so that pairs split across runs of both kinds, in both orders; short
        // ones, which are gathered into the run before them, and ones long enough to stay runs.
        for stretches in [
            vec![(3, 5), (1, 1), (0, 7), (4, 0), (2, 9)],
            vec![(3, 65), (1, 1), (0, 127), (70, 0), (2, 129)],
            // Stretches one short of staying runs of their own, and just long enough to.
            vec![
                (1, SHORT_RUN - 1),
                (1, SHORT_RUN),
                (SHORT_RUN - 1, 1),
                (SHORT_RUN, 1),
            ],
            vec![(0, 1), (1, 0), (0, 3), (5, 6)],
            vec![(16, 0)],
            vec![(0, 16)],
        ] {
            let runs = random_leaves(&mut rng, &stretches);
            let dense = runs.to_vec();
            let sums = runs.map_pairs(|left, right| left + right).to_vec();
            assert_eq!(sums.len(), dense.len() / 2);
            for (sum, pair) in sums.iter().zip(dense.as_chunks::<2>().0) {
                let expected = pair[0] + pair[1];
                assert_eq!((sum.p, sum.q), (expected.p, expected.q), "{stretches:?}");
            }
        }
    }

    #[test]
    fn stored_leaves_alone_prove_as_the_dense_prover() {
        let mut rng = StdRng::seed_from_u64(2);
        // The longest has its rounds' terms summed by several tasks.
        for log_len in [1, 2, 3, 4, 7, 12, 14] {
            assert_same_as_dense(&random_leaves(&mut rng, &[(1 << log_len, 0)]), false);
        }
    }

    #[test]
    fn one_repeated_leaf_proves_as_the_dense_prover() {
        let mut rng = StdRng::seed_from_u64(3);
        for log_len in [1, 2, 3, 4, 7, 12] {
            assert_same_as_dense(&random_leaves(&mut rng, &[(0, 1 << log_len)]), false);
        }
    }

    /// The shape of a stacked GKR input: slabs of a power of two, tallest first, each its real
    /// rows, its padding leaf and its last row, then one leaf to the end.
    #[test]
    fn slabs_with_padding_prove_as_the_dense_prover() {
        let mut rng = StdRng::seed_from_u64(4);
        for (log_len, slabs) in [
            // Padding too short to stay a run of its own, which is stored with its slab.
            (8, vec![(64, 5), (64, 5), (32, 0), (16, 16), (8, 1), (4, 2)]),
            // Padding that stays a run, in slabs of several sizes.
            (9, vec![(256, 5), (128, 1), (64, 64)]),
            (10, vec![(512, 100), (256, 256), (128, 1), (2, 1)]),
            (11, vec![(1024, 0), (512, 300), (256, 255)]),
        ] {
            let mut stretches = Vec::new();
            let mut used = 0;
            for &(slab, real) in &slabs {
                if real == slab {
                    stretches.push((slab, 0));
                } else {
                    stretches.push((real, slab - real - 1));
                    stretches.push((1, 0));
                }
                used += slab;
            }
            stretches.push((0, (1 << log_len) - used));
            let leaves = random_leaves(&mut rng, &stretches);
            assert_eq!(leaves.len(), 1 << log_len);
            assert_same_as_dense(&leaves, false);
        }
    }

    #[test]
    fn stretches_of_any_length_prove_as_the_dense_prover() {
        let mut rng = StdRng::seed_from_u64(5);
        for _ in 0..20 {
            let log_len = 1 + rng.random_range(0..10);
            let mut stretches = Vec::new();
            let mut left = 1usize << log_len;
            while left != 0 {
                let stored = rng.random_range(0..6).min(left);
                left -= stored;
                let repeated = rng.random_range(0..200).min(left);
                left -= repeated;
                stretches.push((stored, repeated));
            }
            assert_same_as_dense(&random_leaves(&mut rng, &stretches), false);
        }
    }

    /// Stretches of more pairs than one task takes, which are summed, folded and paired in
    /// parallel, with pairs split between them.
    #[test]
    fn long_stretches_prove_as_the_dense_prover() {
        let mut rng = StdRng::seed_from_u64(6);
        let pairs = PAIRS_PER_TASK;
        let stretches = [
            (2 * pairs + 952, 2 * pairs + 53),
            (1, 0),
            (2 * pairs + 1, 4 * pairs - 1007),
        ];
        let leaves = random_leaves(&mut rng, &stretches);
        assert_eq!(leaves.len(), 10 * pairs);
        let mut padded = leaves.clone();
        padded.push_repeated(random_frac(&mut rng), 6 * pairs);
        assert_same_as_dense(&padded, false);
    }

    /// A sum that has to be zero: the two provers accept a balanced input and refuse an
    /// unbalanced one alike.
    #[test]
    fn a_zero_sum_is_asserted_as_the_dense_prover_asserts_it() {
        let one = Frac::new(EF::ONE, EF::ONE);
        let minus_three = Frac::new(-EF::from_u32(3), EF::ONE);
        let zero = Frac::new(EF::ZERO, EF::ONE);

        let mut balanced = Runs::default();
        balanced.push_stored(vec![minus_three]);
        balanced.push_repeated(one, 3);
        balanced.push_repeated(zero, 12);
        assert_same_as_dense(&balanced, true);

        // The same with stretches long enough to stay runs.
        let mut balanced = Runs::default();
        balanced.push_stored(vec![Frac::new(-EF::from_u32(100), EF::ONE)]);
        balanced.push_repeated(one, 100);
        balanced.push_repeated(zero, 155);
        assert_same_as_dense(&balanced, true);

        let mut unbalanced = Runs::default();
        unbalanced.push_repeated(one, 4);
        let mut transcript = DuplexSponge::from(default_koalabear_poseidon2_16());
        assert!(matches!(
            fractional_sumcheck_over_runs::<SC, _>(&mut transcript, &unbalanced, true),
            Err(LogupZerocheckError::NonZeroRootSum)
        ));
        assert_same_as_dense(&unbalanced, true);
    }

    #[test]
    fn no_leaves_prove_trivially() {
        assert_same_as_dense(&Runs::default(), true);
    }
}
