use num_bigint::BigUint;
use p3_field::{PrimeField, PrimeField32};
use p3_symmetric::CryptographicPermutation;

use super::{duplex_sponge::DuplexSponge, FiatShamirTranscript};
use crate::{
    multi_field_packing::{checked_num_packed_f_elms, pack_f_to_sf},
    StarkProtocolConfig,
};

/// Multi-field transcript that operates on a sponge over a large `SpongeField`
/// while producing samples in a smaller base field `F`.
///
/// Uses bit-packed observe (base-2^F::bits()) and base-F::ORDER sample
/// expansion for high throughput.
///
/// # Soundness note
///
/// Partial observe buffers are packed with variable length (1..8 values per
/// sponge element). If an adversary could choose *how many* values are observed
/// between flushes, different observe sequences could pack to the same sponge
/// input. Safe usage entails a deterministic observe/sample call pattern, or
/// one that depends only on values already bound into the transcript.
#[derive(Clone, Debug)]
pub struct MultiFieldTranscript<F, SF, P, const WIDTH: usize, const RATE: usize>
where
    F: PrimeField32,
    SF: PrimeField,
    P: CryptographicPermutation<[SF; WIDTH]>,
{
    sponge: DuplexSponge<SF, P, WIDTH, RATE>,
    /// Pending base-field values not yet packed into a sponge-field element.
    observe_buf: Vec<F>,
    /// Buffered base-field samples from the last base-F::ORDER expansion.
    sample_buf: Vec<F>,
    /// Number of `F` elements that fit in one SF element via bit-packing.
    /// = floor(SF::bits() / F::bits())
    num_obs_per_elem: usize,
    /// Number of `F` samples extracted per SF element via base-F::ORDER decomposition.
    num_samples_per_elem: usize,
}

impl<F, SF, P, const WIDTH: usize, const RATE: usize> From<P>
    for MultiFieldTranscript<F, SF, P, WIDTH, RATE>
where
    F: PrimeField32,
    SF: PrimeField + Default + Copy,
    P: CryptographicPermutation<[SF; WIDTH]>,
{
    fn from(perm: P) -> Self {
        Self::new(perm)
    }
}

impl<F, SF, P, const WIDTH: usize, const RATE: usize> MultiFieldTranscript<F, SF, P, WIDTH, RATE>
where
    F: PrimeField32,
    SF: PrimeField + Default + Copy,
    P: CryptographicPermutation<[SF; WIDTH]>,
{
    pub fn new(perm: P) -> Self {
        let num_obs_per_elem = checked_num_packed_f_elms::<F, SF>();
        let num_samples_per_elem = compute_num_samples_per_elem::<F, SF>();

        // Base-F::ORDER decomposition must extract at least 1 digit per squeeze.
        assert!(
            num_samples_per_elem > 0,
            "SF::bits() must be > 1 + BIAS_BITS + F::bits() for base-F::ORDER sampling"
        );

        Self {
            sponge: DuplexSponge::from(perm),
            observe_buf: Vec::with_capacity(num_obs_per_elem),
            sample_buf: Vec::with_capacity(num_samples_per_elem),
            num_obs_per_elem,
            num_samples_per_elem,
        }
    }

    // --- Read-only accessors (for device synchronization) ---

    pub fn sponge_state(&self) -> &[SF; WIDTH] {
        self.sponge.state()
    }

    pub fn absorb_idx(&self) -> usize {
        self.sponge.absorb_idx()
    }

    pub fn sample_idx(&self) -> usize {
        self.sponge.sample_idx()
    }

    pub fn observe_buf(&self) -> &[F] {
        &self.observe_buf
    }

    pub fn sample_buf(&self) -> &[F] {
        &self.sample_buf
    }

    // --- Public API ---

    /// Observe a single base-field value.
    pub fn observe(&mut self, value: F) {
        self.invalidate_samples();
        self.observe_buf.push(value);
        if self.observe_buf.len() == self.num_obs_per_elem {
            let packed = pack_f_to_sf(&self.observe_buf);
            self.sponge.absorb(packed);
            self.observe_buf.clear();
        }
    }

    /// Sample a single base-field value.
    pub fn sample(&mut self) -> F {
        if let Some(val) = self.sample_buf.pop() {
            return val;
        }
        self.flush_observe_buf();
        let squeezed = self.sponge.squeeze();
        self.sample_buf = self.extract_samples(squeezed);
        // Reverse so pop() returns digits in order (b_0 first)
        self.sample_buf.reverse();
        self.sample_buf
            .pop()
            .expect("sample_buf should be non-empty")
    }

    // --- State transition helpers ---
    //
    // Rule: observe-side operations call `invalidate_samples`,
    //       sample-side operations call `flush_observe_buf`,
    //       cross-layer operations (absorb_slice) call both.

    /// Invalidate cached samples. Must be called before any observe-side operation.
    fn invalidate_samples(&mut self) {
        self.sample_buf.clear();
    }

    /// Flush pending `F` observations into the SF sponge by packing and absorbing.
    /// Must be called before any sample-side operation (squeeze).
    fn flush_observe_buf(&mut self) {
        if !self.observe_buf.is_empty() {
            let packed = pack_f_to_sf(&self.observe_buf);
            self.sponge.absorb(packed);
            self.observe_buf.clear();
        }
    }

    /// Directly absorb sponge-field elements (cross-layer: needs both transitions).
    fn absorb_slice(&mut self, slc: &[SF]) {
        self.invalidate_samples();
        self.flush_observe_buf();
        for &elem in slc {
            self.sponge.absorb(elem);
        }
    }

    // --- F↔ SF conversion ---

    /// Extract k base-F::ORDER digits from a sponge-field element.
    ///
    /// Returns digits LSB-first: `[b_0, b_1, ..., b_{k-1}]` where
    /// `val = b_0 + b_1*p + ... + b_{k-1}*p^{k-1} + (discarded high)`.
    fn extract_samples(&self, val: SF) -> Vec<F> {
        let p = BigUint::from(F::ORDER_U32);
        let mut x = val.as_canonical_biguint();
        let mut digits = Vec::with_capacity(self.num_samples_per_elem);
        for _ in 0..self.num_samples_per_elem {
            let remainder = &x % &p;
            x /= &p;
            // remainder < p < 2^32, so this is safe
            let r: u32 = remainder.try_into().unwrap();
            digits.push(F::from_u32(r));
        }
        digits
    }
}

impl<SC, F, SF, P, const WIDTH: usize, const RATE: usize> FiatShamirTranscript<SC>
    for MultiFieldTranscript<F, SF, P, WIDTH, RATE>
where
    F: PrimeField32,
    SF: PrimeField + Default + Copy + Send + Sync,
    P: CryptographicPermutation<[SF; WIDTH]> + Clone + Send + Sync,
    SC: StarkProtocolConfig<F = F>,
    SC::Digest: AsRef<[SF]>,
{
    fn observe(&mut self, value: F) {
        self.observe(value);
    }

    fn sample(&mut self) -> F {
        self.sample()
    }

    fn observe_commit(&mut self, digest: SC::Digest) {
        self.absorb_slice(digest.as_ref());
    }
}

const BIAS_BITS: usize = 100;

/// Returns the largest `k` such that extracting `k` base-`p` digits from a
/// uniform `SF` element has statistical distance at most `2^{-BIAS_BITS}` from
/// uniform, where `p = F::ORDER` and `q = SF::order()`.
///
/// # Bias analysis
///
/// Extracting `k` base-`p` digits from a uniform `X ∈ Z_q` is equivalent to
/// computing `X mod p^k`. Write `q = m * p^k + r` with `0 <= r < p^k`. Then:
///
/// - residues `0, ..., r - 1` each have `m + 1` preimages in `[0, q)`,
/// - residues `r, ..., p^k - 1` each have only `m`.
///
/// The exact statistical distance from uniform is `r * (p^k - r) / (q * p^k)`,
/// which by AM-GM is at most `p^k / (4q)`. We pick the largest `k` satisfying
/// `p^k * 2^(BIAS_BITS - 2) <= q`.
fn compute_num_samples_per_elem<F: PrimeField32, SF: PrimeField>() -> usize {
    let q = SF::order();
    let p = BigUint::from(F::ORDER_U32);

    let mut k = 0usize;
    let mut p_pow = BigUint::from(1u32); // p^k

    loop {
        let next = &p_pow * &p; // p^(k+1)
        if (&next << (BIAS_BITS - 2)) > q {
            break;
        }
        p_pow = next;
        k += 1;
    }
    k
}

#[cfg(test)]
mod tests {
    use p3_bn254::Bn254;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::config::multi_field_packing::pack_f_to_sf;

    type TestTranscript = MultiFieldTranscript<KoalaBear, Bn254, MockPerm, 3, 2>;

    #[derive(Clone, Debug)]
    struct MockPerm;

    impl p3_symmetric::Permutation<[Bn254; 3]> for MockPerm {
        fn permute_mut(&self, state: &mut [Bn254; 3]) {
            let [a, b, c] = *state;
            state[0] = a + b + c + Bn254::ONE;
            state[1] = a + b * Bn254::TWO + c;
            state[2] = a + b + c * Bn254::TWO;
        }
    }

    impl CryptographicPermutation<[Bn254; 3]> for MockPerm {}

    #[test]
    fn test_constants_bn254_koalabear() {
        let t = TestTranscript::new(MockPerm);
        assert_eq!(t.num_obs_per_elem, 8);
        assert_eq!(t.num_samples_per_elem, 5);
    }

    #[test]
    fn test_pack_correctness() {
        let vals: Vec<KoalaBear> = vec![
            KoalaBear::from_u32(1u32),
            KoalaBear::from_u32(2u32),
            KoalaBear::from_u32(3u32),
        ];
        let packed: Bn254 = pack_f_to_sf(&vals);
        let expected = BigUint::from(1u64)
            + BigUint::from(2u64) * (BigUint::from(1u64) << 31)
            + BigUint::from(3u64) * (BigUint::from(1u64) << 62);
        assert_eq!(packed.as_canonical_biguint(), expected);
    }

    #[test]
    fn test_expand_correctness() {
        let t = TestTranscript::new(MockPerm);
        let p_f = Bn254::from_u32(KoalaBear::ORDER_U32);
        let val = Bn254::from_u32(1) + Bn254::from_u32(2) * p_f + Bn254::from_u32(3) * p_f * p_f;
        let digits = t.extract_samples(val);
        assert_eq!(digits.len(), 5);
        assert_eq!(digits[0], KoalaBear::from_u32(1u32));
        assert_eq!(digits[1], KoalaBear::from_u32(2u32));
        assert_eq!(digits[2], KoalaBear::from_u32(3u32));
        for digit in &digits[3..5] {
            assert_eq!(*digit, KoalaBear::ZERO);
        }
    }

    #[test]
    fn test_observe_invalidates_sample_buf() {
        let mut t1 = TestTranscript::new(MockPerm);
        let mut t2 = t1.clone();

        t1.observe(KoalaBear::from_u32(1u32));
        t2.observe(KoalaBear::from_u32(1u32));

        let s1 = t1.sample();
        let s2 = t2.sample();
        assert_eq!(s1, s2);

        // Observe on t1 only — should clear t1's remaining sample_buf
        t1.observe(KoalaBear::from_u32(2u32));

        let s1 = t1.sample();
        let s2 = t2.sample();
        assert_ne!(s1, s2, "observe should invalidate buffered samples");
    }

    #[test]
    fn test_observe_sample_sequence_is_deterministic() {
        let run = || {
            let mut t = TestTranscript::new(MockPerm);
            let mut out = Vec::new();
            for i in 0..16u32 {
                t.observe(KoalaBear::from_u32(i + 1));
                if i % 2 == 0 {
                    out.push(t.sample());
                }
            }
            out
        };
        let a = run();
        let b = run();
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
    }

    #[test]
    fn test_partial_observe_buf_flushed_before_commit() {
        let mut t1 = TestTranscript::new(MockPerm);
        let mut t2 = TestTranscript::new(MockPerm);

        // Observe 3 values (partial buf), then commit
        for i in 0..3u32 {
            t1.observe(KoalaBear::from_u32(i));
            t2.observe(KoalaBear::from_u32(i));
        }
        let commit_val = Bn254::from_u64(777);
        t1.absorb_slice(&[commit_val]);
        t2.absorb_slice(&[commit_val]);

        for _ in 0..5 {
            assert_eq!(t1.sample(), t2.sample());
        }

        // Without the partial observe, samples should differ
        let mut with_obs = TestTranscript::new(MockPerm);
        for i in 0..3u32 {
            with_obs.observe(KoalaBear::from_u32(i));
        }
        with_obs.absorb_slice(&[commit_val]);
        let mut without_obs = TestTranscript::new(MockPerm);
        without_obs.absorb_slice(&[commit_val]);
        assert_ne!(with_obs.sample(), without_obs.sample());
    }
}
