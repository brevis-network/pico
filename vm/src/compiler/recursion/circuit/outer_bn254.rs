//! Gnark-target circuit twins of the **outer** (BN254-Poseidon2) primitives used by the embed
//! proof: [`MultiFieldTranscript`] and [`MultiFieldHasher`] over the width-3 BN254 permutation.
//!
//! These are the building blocks of the wrap circuit that verifies the embed proof on-chain: its
//! transcript and Merkle hashing lower to **native** BN254 `Permute` opcodes (cheap in gnark),
//! while field arithmetic stays emulated KoalaBear.
//!
//! Every shape constant here is derived from the Rust-side embed config rather than redeclared, so
//! the twin cannot drift from the prover.
//!
//! Twinned semantics (validated by the `test_outer_twins` known-answer harness via gnark solve):
//! - duplex sponge: absorb overwrites `state[absorb_idx++]`; permutes when the rate (2) fills;
//!   squeeze permutes if absorbs are pending or samples are exhausted, then returns
//!   `state[--sample_idx]` (i.e. lane 1 first, then lane 0).
//! - observe packs 8 KoalaBear felts into one BN254 element at base 2^31, little-endian (`f_0` in
//!   the lowest limb); a partial buffer is packed as-is before any squeeze.
//! - sample extracts 5 base-`p` digits per squeezed BN254 element (LSB-first). In-circuit the
//!   digits (and the quotient) are read from the witness stream and bound by the recomposition
//!   constraint `squeezed == Σ digit_i·p^i + rem·p^5`; `felt2var` canonicalizes each digit mod `p`.
//! - `check_witness(0, w)` observes nothing and asserts nothing, matching the Rust trait default.
//!   Getting this wrong skews the transcript from that point on.
//!
//! SSA discipline: both `Permute` (BN254) and `PermuteKoalaBear` overwrite their argument slots in
//! place. Every permutation input is copied into fresh variables first (`fresh_var`), and any
//! value that must outlive a later permutation is copied out again.
//!
//! Sampling soundness: the recomposition constraint alone would NOT pin a unique `(digits, rem)`
//! tuple — see [`canonical_rem_max`] and [`OuterTranscript::sample`] for the canonical-decomposition
//! gadget that does, and for why a single upper bound is not enough.
//!
//! [`MultiFieldTranscript`]: pico_mle_core::transcript::multi_field::MultiFieldTranscript
//! [`MultiFieldHasher`]: pico_mle_core::hasher::MultiFieldHasher

use p3_bn254::Bn254;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;

use crate::{
    compiler::recursion::ir::{Builder, DslIr, Ext, Felt, Var},
    configs::{config::FieldGenericConfig, field_config::KoalaBearBn254},
    mle::config::koala_bear_bn254_poseidon2::EMBED_FELTS_PER_BN254,
    primitives::consts::{MULTI_FIELD_CHALLENGER_RATE, MULTI_FIELD_CHALLENGER_WIDTH},
};

type FC = KoalaBearBn254;
type F = KoalaBear;
type N = Bn254;
type EmbedExt = Ext<F, <FC as FieldGenericConfig>::EF>;

const WIDTH: usize = MULTI_FIELD_CHALLENGER_WIDTH;
const RATE: usize = MULTI_FIELD_CHALLENGER_RATE;
/// KoalaBear felts packed per BN254 element (base 2^31, injective).
pub const OBS_PER_ELEM: usize = EMBED_FELTS_PER_BN254;
/// Base-`p` digits sampled per squeezed BN254 element (`p^5 · 2^98 ≤ q`).
pub const SAMPLES_PER_ELEM: usize = 5;
/// Bit width used for both range bounds on the decomposition remainder. The honest quotient
/// satisfies `⌊(q-1)/p^5⌋ < 2^99`, so 100 bits admits every honest value with room to spare, and
/// both `rem` and `REM_MAX - rem` fit.
pub const REM_BITS: usize = 100;

/// Inclusive upper bound on the decomposition remainder: `⌊q / p^5⌋ − 1`.
///
/// # Why this exact value, and why a box constraint cannot be tight
///
/// The recomposition `squeezed == Σ digitᵢ·pⁱ + rem·p⁵` is an identity mod `q`. It pins a unique
/// tuple only if every tuple the circuit admits has a recomposed *integer* below `q` — then no two
/// admissible tuples can differ by a multiple of `q`, and integer base-`p⁵` decomposition with
/// digits in `[0, p)` is unique.
///
/// With digits bounded by `p` (which `felt2var` enforces) the largest admissible integer is
/// `rem·p⁵ + p⁵ − 1`, so soundness needs `(rem + 1)·p⁵ ≤ q`, i.e. `rem ≤ ⌊q/p⁵⌋ − 1`.
///
/// The largest remainder an *honest* decomposition can produce is `⌊(q−1)/p⁵⌋`, which equals
/// `⌊q/p⁵⌋` (since `p⁵ ∤ q`) — one more than the sound bound. So no single box constraint on `rem`
/// is both sound and complete; making it complete as well needs a lexicographic comparison of the
/// whole `(rem, digits)` tuple against `q`'s own decomposition.
///
/// We take the sound bound. The cost is a completeness gap: a squeezed element in
/// `[(⌊q/p⁵⌋)·p⁵, q)` has no admissible witness, so an honest prover cannot wrap that proof. That
/// interval has size `q mod p⁵ < p⁵`, i.e. probability `< 2^-98` per squeeze, ~`2^-90` across a
/// whole wrap circuit. Failing that rarely — visibly, at witness generation — is the right trade
/// against carrying a challenge-steering hole into production; the lexicographic gadget is the
/// upgrade if the gap ever needs closing.
pub fn canonical_rem_max() -> N {
    use num_bigint::BigUint;
    use p3_field::Field;

    let p = BigUint::from(F::ORDER_U32);
    let bound = N::order() / p.pow(SAMPLES_PER_ELEM as u32) - BigUint::from(1u32);
    let two64 = N::from_u64(1 << 32) * N::from_u64(1 << 32);
    bound
        .to_u64_digits()
        .iter()
        .rev()
        .fold(N::ZERO, |acc, &limb| acc * two64 + N::from_u64(limb))
}

/// Fresh copy of a Var (new id) so the in-place BN254 permutation can never clobber a live one.
fn fresh_var(builder: &mut Builder<FC>, x: Var<N>) -> Var<N> {
    builder.eval(x + N::ZERO)
}

/// Permute a width-3 BN254 state in-circuit, SSA-safely.
fn bn254_permute_ssa(builder: &mut Builder<FC>, input: [Var<N>; WIDTH]) -> [Var<N>; WIDTH] {
    let st: [Var<N>; WIDTH] = core::array::from_fn(|i| fresh_var(builder, input[i]));
    builder.push_op(DslIr::CircuitPoseidon2Permute(st));
    st
}

/// Pack up to 8 KoalaBear felts into one BN254 var at base 2^31, little-endian (`f_0` lowest).
/// Mirrors `pack_f_to_sf`.
fn pack_felts_to_var(builder: &mut Builder<FC>, felts: &[Felt<F>]) -> Var<N> {
    debug_assert!(!felts.is_empty() && felts.len() <= OBS_PER_ELEM);
    let base = N::from_u64(1 << 31);
    let mut acc: Var<N> = builder.constant(N::ZERO);
    for &f in felts.iter().rev() {
        let v = builder.felt2var_circuit(f);
        acc = builder.eval(acc * base + v);
    }
    acc
}

// ---------------------------------------------------------------------------------------------
// Duplex sponge (width 3 / rate 2) over the BN254 permutation.
// ---------------------------------------------------------------------------------------------

pub struct OuterSponge {
    state: [Var<N>; WIDTH],
    absorb_idx: usize,
    sample_idx: usize,
}

impl OuterSponge {
    pub fn new(builder: &mut Builder<FC>) -> Self {
        Self {
            state: core::array::from_fn(|_| builder.constant(N::ZERO)),
            absorb_idx: 0,
            sample_idx: 0,
        }
    }

    fn permute(&mut self, builder: &mut Builder<FC>) {
        self.state = bn254_permute_ssa(builder, self.state);
    }

    pub fn absorb(&mut self, builder: &mut Builder<FC>, value: Var<N>) {
        self.state[self.absorb_idx] = value;
        self.absorb_idx += 1;
        if self.absorb_idx == RATE {
            self.permute(builder);
            self.absorb_idx = 0;
            self.sample_idx = RATE;
        }
    }

    pub fn squeeze(&mut self, builder: &mut Builder<FC>) -> Var<N> {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            self.permute(builder);
            self.absorb_idx = 0;
            self.sample_idx = RATE;
        }
        self.sample_idx -= 1;
        // Fresh copy: the returned var must stay stable across future permutations.
        fresh_var(builder, self.state[self.sample_idx])
    }
}

// ---------------------------------------------------------------------------------------------
// Fiat–Shamir transcript twin of `MultiFieldTranscript`.
// ---------------------------------------------------------------------------------------------

pub struct OuterTranscript {
    sponge: OuterSponge,
    observe_buf: Vec<Felt<F>>,
    sample_buf: Vec<Felt<F>>,
}

impl OuterTranscript {
    pub fn new(builder: &mut Builder<FC>) -> Self {
        Self {
            sponge: OuterSponge::new(builder),
            observe_buf: vec![],
            sample_buf: vec![],
        }
    }

    pub fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<F>) {
        self.sample_buf.clear();
        self.observe_buf.push(value);
        if self.observe_buf.len() == OBS_PER_ELEM {
            let packed = pack_felts_to_var(builder, &self.observe_buf);
            self.sponge.absorb(builder, packed);
            self.observe_buf.clear();
        }
    }

    fn flush_observe_buf(&mut self, builder: &mut Builder<FC>) {
        if !self.observe_buf.is_empty() {
            let packed = pack_felts_to_var(builder, &self.observe_buf);
            self.sponge.absorb(builder, packed);
            self.observe_buf.clear();
        }
    }

    /// Absorb sponge-field digests directly (`observe_commit`).
    pub fn observe_digest(&mut self, builder: &mut Builder<FC>, digest: &[Var<N>]) {
        self.sample_buf.clear();
        self.flush_observe_buf(builder);
        for &d in digest {
            self.sponge.absorb(builder, d);
        }
    }

    /// Sample one KoalaBear felt. On an empty sample buffer this squeezes one BN254 element and
    /// reads its 5 base-`p` digits (plus the quotient) from the witness stream, binding them with
    /// the recomposition constraint.
    pub fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<F> {
        if let Some(f) = self.sample_buf.pop() {
            return f;
        }
        self.flush_observe_buf(builder);
        let squeezed = self.sponge.squeeze(builder);

        // Witness order per squeeze: digit_0 .. digit_4 (felts), then the remainder (var).
        let digits: Vec<Felt<F>> = (0..SAMPLES_PER_ELEM)
            .map(|_| builder.witness_felt())
            .collect();
        let rem: Var<N> = builder.witness_var();
        // Canonical-decomposition gadget: `0 <= rem <= REM_MAX`.
        //
        // BOTH bounds are load-bearing. The upper bound alone is not enough: `REM_MAX - rem` is
        // computed mod `q`, so without a width bound on `rem` itself a prover could pick
        // `rem ≈ q - k`, whose difference from `REM_MAX` wraps back to a small value and passes the
        // slack check while contributing `-k·p^5` to the recomposition. The width bound alone is the
        // pre-existing gap this closes. Together they confine `rem` to the honest interval, and the
        // decomposition — hence every sampled challenge — is unique.
        let _ = builder.num2bits_v_circuit(rem, REM_BITS);
        let rem_max: Var<N> = builder.constant(canonical_rem_max());
        let slack: Var<N> = builder.eval(rem_max - rem);
        let _ = builder.num2bits_v_circuit(slack, REM_BITS);

        // squeezed == Σ digit_i·p^i + rem·p^5   (felt2var canonicalizes digits mod p).
        let p = N::from_u32(F::ORDER_U32);
        let mut acc: Var<N> = builder.constant(N::ZERO);
        let mut p_pow = N::ONE;
        for &d in &digits {
            let dv = builder.felt2var_circuit(d);
            acc = builder.eval(acc + dv * p_pow);
            p_pow *= p;
        }
        acc = builder.eval(acc + rem * p_pow);
        builder.assert_var_eq(acc, squeezed);

        // LSB-first digits; pop() must return digit_0 first.
        self.sample_buf = digits;
        self.sample_buf.reverse();
        self.sample_buf.pop().expect("SAMPLES_PER_ELEM > 0")
    }

    /// Observe an extension element as its four base limbs (matches
    /// `FiatShamirTranscript::observe_ext`).
    pub fn observe_ext(&mut self, builder: &mut Builder<FC>, value: EmbedExt) {
        let limbs: [Felt<F>; 4] = core::array::from_fn(|_| builder.uninit());
        builder.push_op(DslIr::CircuitExt2Felt(limbs, value));
        for f in limbs {
            self.observe(builder, f);
        }
    }

    /// Four samples packed as the extension limbs (matches `FiatShamirTranscript::sample_ext`).
    pub fn sample_ext(&mut self, builder: &mut Builder<FC>) -> EmbedExt {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.felts2ext(&[a, b, c, d])
    }

    /// Low `nb_bits` of one sample (matches `FiatShamirTranscript::sample_bits`).
    pub fn sample_bits(&mut self, builder: &mut Builder<FC>, nb_bits: usize) -> Vec<Var<N>> {
        let f = self.sample(builder);
        let mut bits = builder.num2bits_f_circuit(f);
        bits.truncate(nb_bits);
        bits
    }

    /// Observe the witness felt, then require `nb_bits` sampled low bits to be zero.
    ///
    /// `nb_bits == 0` is a no-op — it must *not* observe (see module docs).
    pub fn check_witness(&mut self, builder: &mut Builder<FC>, nb_bits: usize, witness: Felt<F>) {
        if nb_bits == 0 {
            return;
        }
        self.observe(builder, witness);
        for bit in self.sample_bits(builder, nb_bits) {
            builder.assert_var_eq(bit, N::ZERO);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Merkle hasher twins of `MultiFieldHasher` (+ `TruncatedPermutation`) over 1-element digests.
// ---------------------------------------------------------------------------------------------

/// `MultiFieldHasher::hash_iter` twin: overwrite-mode sponge, 16 felts per permutation (2 rate
/// lanes × 8 packed felts), digest = lane 0.
///
/// A partial trailing block overwrites only the lanes it fills; the rest carry over from the
/// previous permutation, exactly as on the Rust side.
pub fn outer_hash(builder: &mut Builder<FC>, input: &[Felt<F>]) -> Var<N> {
    let mut state: [Var<N>; WIDTH] = core::array::from_fn(|_| builder.constant(N::ZERO));
    for block in input.chunks(RATE * OBS_PER_ELEM) {
        for (lane, lane_felts) in block.chunks(OBS_PER_ELEM).enumerate() {
            state[lane] = pack_felts_to_var(builder, lane_felts);
        }
        state = bn254_permute_ssa(builder, state);
    }
    fresh_var(builder, state[0])
}

/// `TruncatedPermutation<_, 2, 1, 3>` twin: node compression of two 1-element digests.
pub fn outer_compress(builder: &mut Builder<FC>, left: Var<N>, right: Var<N>) -> Var<N> {
    let zero: Var<N> = builder.constant(N::ZERO);
    let state = bn254_permute_ssa(builder, [left, right, zero]);
    fresh_var(builder, state[0])
}

#[cfg(test)]
mod tests {
    use pico_mle_core::FiatShamirTranscript;

    use super::*;
    use crate::mle::config::koala_bear_bn254_poseidon2::{
        default_bn254_poseidon2_3, EmbedTranscript, KoalaBearBn254Poseidon2Config, EMBED_HASH_RATE,
    };

    type SC = KoalaBearBn254Poseidon2Config;

    /// [`OBS_PER_ELEM`] must be the *real* transcript's pack width: the flush happens on the felt
    /// that fills the buffer, not one earlier or later. Read straight off the Rust transcript's
    /// buffer accessors so a change in `checked_num_packed_f_elms` breaks this test, not the twin.
    #[test]
    fn obs_per_elem_matches_the_rust_transcript() {
        let mut t = EmbedTranscript::from(default_bn254_poseidon2_3());
        for i in 0..OBS_PER_ELEM as u32 - 1 {
            FiatShamirTranscript::<SC>::observe(&mut t, F::from_u32(i + 1));
        }
        assert_eq!(t.observe_buf().len(), OBS_PER_ELEM - 1, "flushed too early");
        FiatShamirTranscript::<SC>::observe(&mut t, F::ONE);
        assert!(t.observe_buf().is_empty(), "did not flush on the 8th felt");
    }

    /// [`SAMPLES_PER_ELEM`] must be the number of digits the Rust transcript extracts per squeeze:
    /// one `sample()` consumes the first digit and leaves the rest buffered.
    #[test]
    fn samples_per_elem_matches_the_rust_transcript() {
        let mut t = EmbedTranscript::from(default_bn254_poseidon2_3());
        FiatShamirTranscript::<SC>::observe(&mut t, F::ONE);
        let _ = FiatShamirTranscript::<SC>::sample(&mut t);
        assert_eq!(t.sample_buf().len(), SAMPLES_PER_ELEM - 1);
    }

    /// The felts-per-permutation the leaf-hash twin chunks by is the rate the Rust `EmbedHash` is
    /// instantiated with.
    #[test]
    fn leaf_hash_block_matches_the_rust_hasher_rate() {
        assert_eq!(RATE * OBS_PER_ELEM, EMBED_HASH_RATE);
    }

    /// `REM_BITS` must be wide enough for BOTH gadget bounds: `rem` itself and `REM_MAX - rem`.
    #[test]
    fn rem_bits_covers_both_canonical_bounds() {
        use num_bigint::BigUint;
        use p3_field::{Field, PrimeField};

        let p = BigUint::from(F::ORDER_U32);
        let bound = N::order() / p.pow(SAMPLES_PER_ELEM as u32) - BigUint::from(1u32);
        assert!(
            bound.bits() as usize <= REM_BITS,
            "REM_MAX needs {} bits, REM_BITS is {REM_BITS}",
            bound.bits()
        );
        // The gadget's field constant must equal the integer bound it stands for.
        assert_eq!(canonical_rem_max().as_canonical_biguint(), bound);
    }

    /// The bound is exactly the canonical one: one higher and the recomposed integer can reach `q`,
    /// which is precisely the wraparound that admits a second tuple for the same squeezed element.
    #[test]
    fn canonical_bound_is_the_largest_that_cannot_wrap() {
        use num_bigint::BigUint;
        use p3_field::{Field, PrimeField};

        let p = BigUint::from(F::ORDER_U32);
        let p5 = p.pow(SAMPLES_PER_ELEM as u32);
        let q = N::order();
        let r = canonical_rem_max().as_canonical_biguint();

        // Largest integer representable at the bound stays below q — no wraparound, so the
        // decomposition is injective.
        let max_at_bound = &r * &p5 + (&p5 - BigUint::from(1u32));
        assert!(max_at_bound < q, "the bound already permits wraparound");

        // One step higher does wrap, so the bound is the largest sound one, not a conservative
        // guess.
        let max_one_over = (&r + BigUint::from(1u32)) * &p5 + (&p5 - BigUint::from(1u32));
        assert!(max_one_over >= q, "the bound is looser than it needs to be");

        // And it is exactly one below the largest remainder an honest decomposition can produce —
        // that difference IS the documented completeness gap, so pin it rather than let it drift.
        let honest_max = (&q - BigUint::from(1u32)) / &p5;
        assert_eq!(honest_max, &r + BigUint::from(1u32));

        // The gap's size: squeezed elements with no admissible witness, as a fraction of the field.
        let unwrappable = &q - &honest_max * &p5;
        assert!(unwrappable < p5, "gap wider than one p^5 block");
        assert!(
            (q.bits() - unwrappable.bits()) >= 98,
            "completeness gap is larger than the documented 2^-98 per squeeze"
        );
    }

    /// A prover must not be able to satisfy the slack check with a huge `rem` whose difference from
    /// `REM_MAX` wraps: that is why the width bound on `rem` itself is kept alongside the upper
    /// bound. Confirm the attack values the width bound rules out really do pass the slack check.
    #[test]
    fn wrapped_remainders_pass_slack_and_are_caught_only_by_the_width_bound() {
        use num_bigint::BigUint;
        use p3_field::{Field, PrimeField};

        let q = N::order();
        let r = canonical_rem_max().as_canonical_biguint();
        // rem = q - k for small k: slack = REM_MAX - rem = REM_MAX + k mod q, which is small.
        for k in [1u32, 7, 1000] {
            let rem = &q - BigUint::from(k);
            let slack = (&r + BigUint::from(k)) % &q;
            assert!(
                slack.bits() as usize <= REM_BITS,
                "slack check alone would accept rem = q - {k}"
            );
            // ... and the width bound on `rem` is what rejects it.
            assert!(
                rem.bits() as usize > REM_BITS,
                "the width bound must reject rem = q - {k}"
            );
        }
    }
}
