use std::{fmt::Debug, marker::PhantomData};

use derivative::Derivative;
use p3_field::Field;
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
#[cfg(feature = "multi-field-transcript")]
use {
    super::multi_field_packing::{checked_num_packed_f_elms, pack_f_to_sf},
    itertools::Itertools,
    p3_field::{PrimeField, PrimeField32},
    p3_symmetric::CryptographicPermutation,
};

/// Trait abstracting Merkle tree hash operations. This trait is used as part of the definition of
/// the [`StarkProtocolConfig`](crate::StarkProtocolConfig).
///
/// The `MerkleHasher` is parameterized over the base field `F` used as leaves,
/// and provides a `Digest` type for internal nodes.
pub trait MerkleHasher: 'static + Clone + Send + Sync {
    type F: Field;
    type Digest: 'static + Copy + Send + Sync;

    /// Hash a slice of field elements into a digest (used for leaf hashing).
    fn hash_slice(&self, vals: &[Self::F]) -> Self::Digest;

    /// Compress two digests into one (used for internal Merkle tree nodes).
    fn compress(&self, left: Self::Digest, right: Self::Digest) -> Self::Digest;

    /// Compress a vector of digests (must be power-of-two length) into a single digest
    /// by repeated binary compression.
    fn tree_compress(&self, mut hashes: Vec<Self::Digest>) -> Self::Digest {
        debug_assert!(hashes.len().is_power_of_two());
        while hashes.len() > 1 {
            let mut next = Vec::with_capacity(hashes.len() / 2);
            for pair in hashes.as_chunks::<2>().0 {
                next.push(self.compress(pair[0], pair[1]));
            }
            hashes = next;
        }
        hashes.pop().unwrap()
    }
}

/// [MerkleHasher] implementation built from a cryptographic hash function and a compression
/// function. This struct is intended for use by the protocol verifier. Prover backends may use
/// independent but functionally equivalent implementations.
///
/// The compression function does not need to be collision-resistant and only needs to be a pseudo-cryptographic function: <https://eprint.iacr.org/2026/089>.
#[derive(Derivative, derive_new::new)]
#[derivative(
    Clone(bound = "H: Clone, C: Clone"),
    Debug(bound = "H: Debug, C: Debug")
)]
pub struct Hasher<F, Digest, H, C> {
    hash: H,
    compress: C,
    _phantom: PhantomData<(F, Digest)>,
}

impl<F, Digest, H, C> MerkleHasher for Hasher<F, Digest, H, C>
where
    F: Field,
    Digest: 'static + Copy + Send + Sync,
    H: 'static + Send + Sync + CryptographicHasher<F, Digest>,
    C: 'static + Send + Sync + PseudoCompressionFunction<Digest, 2>,
{
    type F = F;
    type Digest = Digest;

    fn hash_slice(&self, vals: &[Self::F]) -> Self::Digest {
        self.hash.hash_slice(vals)
    }

    fn compress(&self, left: Self::Digest, right: Self::Digest) -> Self::Digest {
        self.compress.compress([left, right])
    }
}

/// A padding-free, overwrite-mode sponge that permutes natively over `PF` but accepts elements of
/// `F: PrimeField32`, packing them at base-2^(F::bits()).
///
/// This is the leaf hasher of the *outer* ("embed") protocol config, whose Merkle digests are
/// single `PF` elements so that an on-chain circuit over `PF` recomputes each node with one native
/// permutation instead of a few hundred emulated `F` permutations.
///
/// It differs from Plonky3's `MultiField32PaddingFreeSponge`, which packs at base-2^32: for
/// KoalaBear (31-bit) base-2^31 packing of 8 elements is injective into BN254, whereas base-2^32
/// packing of 8 elements can exceed the BN254 modulus. [`checked_num_packed_f_elms`] asserts the
/// injectivity of the chosen rate at construction time.
///
/// # Semantics (load-bearing — the circuit twin must match bit for bit)
///
/// Each `RATE` felts form one block that overwrites the first `RATE / num_f_elms` state lanes and
/// is followed by one permutation. A **partial** trailing block only overwrites the lanes it fills:
/// the remaining lanes keep the value left there by the previous permutation (they are *not*
/// zeroed), and a partial lane is packed at its actual length. Empty input permutes zero times and
/// returns the zero digest.
#[cfg(feature = "multi-field-transcript")]
#[derive(Clone, Debug)]
pub struct MultiFieldHasher<F, PF, P, const WIDTH: usize, const RATE: usize, const OUT: usize> {
    permutation: P,
    num_f_elms: usize,
    _phantom: PhantomData<(F, PF)>,
}

#[cfg(feature = "multi-field-transcript")]
impl<F, PF, P, const WIDTH: usize, const RATE: usize, const OUT: usize>
    MultiFieldHasher<F, PF, P, WIDTH, RATE, OUT>
where
    F: PrimeField32,
    PF: PrimeField,
{
    pub fn new(permutation: P) -> Self {
        let num_f_elms = checked_num_packed_f_elms::<F, PF>();

        Self {
            permutation,
            num_f_elms,
            _phantom: PhantomData,
        }
    }
}

#[cfg(feature = "multi-field-transcript")]
impl<F, PF, P, const WIDTH: usize, const RATE: usize, const OUT: usize>
    CryptographicHasher<F, [PF; OUT]> for MultiFieldHasher<F, PF, P, WIDTH, RATE, OUT>
where
    F: PrimeField32,
    PF: PrimeField + Default + Copy,
    P: CryptographicPermutation<[PF; WIDTH]>,
{
    fn hash_iter<I>(&self, input: I) -> [PF; OUT]
    where
        I: IntoIterator<Item = F>,
    {
        let mut state = [PF::default(); WIDTH];
        for block_chunk in &input.into_iter().chunks(RATE) {
            for (chunk_id, chunk) in (&block_chunk.chunks(self.num_f_elms))
                .into_iter()
                .enumerate()
            {
                state[chunk_id] = pack_f_to_sf(&chunk.collect_vec());
            }
            state = self.permutation.permute(state);
        }

        state[..OUT].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;
    use crate::{
        config::koala_bear_poseidon2::default_koalabear_poseidon2_16,
        p3_symmetric::{PaddingFreeSponge, TruncatedPermutation},
    };

    type Perm = Poseidon2KoalaBear<16>;
    type KbHasher = Hasher<
        KoalaBear,
        [KoalaBear; 8],
        PaddingFreeSponge<Perm, 16, 8, 8>,
        TruncatedPermutation<Perm, 2, 8, 16>,
    >;

    fn kb_hasher() -> KbHasher {
        let perm = default_koalabear_poseidon2_16();
        Hasher::new(
            PaddingFreeSponge::new(perm.clone()),
            TruncatedPermutation::new(perm),
        )
    }

    /// The default `tree_compress` must equal an explicit pairwise binary reduction.
    #[test]
    fn tree_compress_matches_manual_pairwise() {
        let hasher = kb_hasher();
        let leaves: Vec<[KoalaBear; 8]> = (0..4u32)
            .map(|i| hasher.hash_slice(&[KoalaBear::from_u32(i + 1)]))
            .collect();
        let left = hasher.compress(leaves[0], leaves[1]);
        let right = hasher.compress(leaves[2], leaves[3]);
        let expected = hasher.compress(left, right);
        assert_eq!(hasher.tree_compress(leaves), expected);
    }

    /// Leaf hashing is deterministic for identical input.
    #[test]
    fn hash_slice_is_deterministic() {
        let hasher = kb_hasher();
        let v: Vec<KoalaBear> = (0..5u32).map(|i| KoalaBear::from_u32(i + 1)).collect();
        assert_eq!(hasher.hash_slice(&v), hasher.hash_slice(&v));
    }
}

/// Semantics pins for [`MultiFieldHasher`]. Every property asserted here is replicated by the
/// on-chain circuit twin (`outer_hash` in the vm crate), so a change to any of them is a
/// consensus-breaking change, not a refactor.
#[cfg(all(test, feature = "multi-field-transcript"))]
mod multi_field_hasher_tests {
    use p3_bn254::Bn254;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_symmetric::{CryptographicPermutation, Permutation};

    use super::*;

    type F = KoalaBear;
    type N = Bn254;
    /// Same shape as the embed config: width 3, rate 16 felts (2 lanes × 8), 1-element digest.
    type TestHasher = MultiFieldHasher<F, N, MockPerm, 3, 16, 1>;

    /// Non-linear enough that lane mix-ups and missing permutations cannot cancel out.
    #[derive(Clone, Debug)]
    struct MockPerm;

    impl Permutation<[N; 3]> for MockPerm {
        fn permute_mut(&self, state: &mut [N; 3]) {
            let [a, b, c] = *state;
            state[0] = a * a + b + N::from_u32(7);
            state[1] = b * b + c + N::TWO;
            state[2] = c * c + a + N::ONE;
        }
    }

    impl CryptographicPermutation<[N; 3]> for MockPerm {}

    fn felts(range: std::ops::Range<u32>) -> Vec<F> {
        range.map(|i| F::from_u32(i * 131 + 7)).collect()
    }

    fn pack(buf: &[F]) -> N {
        crate::multi_field_packing::pack_f_to_sf(buf)
    }

    /// A full 16-felt block is two packed lanes plus one permutation, and the digest is lane 0.
    #[test]
    fn full_block_is_two_lanes_and_one_permutation() {
        let input = felts(0..16);
        let expected = MockPerm.permute([pack(&input[..8]), pack(&input[8..]), N::ZERO]);
        assert_eq!(TestHasher::new(MockPerm).hash_slice(&input), [expected[0]]);
    }

    /// A partial trailing block overwrites only the lanes it fills: lanes it does not reach keep
    /// the previous permutation's output rather than being zeroed. This carry-over is the semantic
    /// most likely to be "cleaned up" by mistake.
    #[test]
    fn partial_trailing_block_carries_over_untouched_lanes() {
        let input = felts(0..24);
        let after_first = MockPerm.permute([pack(&input[..8]), pack(&input[8..16]), N::ZERO]);
        // Second block fills lane 0 only; lanes 1 and 2 survive from `after_first`.
        let expected = MockPerm.permute([pack(&input[16..]), after_first[1], after_first[2]]);
        assert_eq!(TestHasher::new(MockPerm).hash_slice(&input), [expected[0]]);

        // Zeroing the untouched lanes would give a different digest — the carry-over is observable.
        let zeroed = MockPerm.permute([pack(&input[16..]), N::ZERO, N::ZERO]);
        assert_ne!(expected[0], zeroed[0]);
    }

    /// A short input still costs exactly one permutation, over the zero initial state.
    #[test]
    fn short_input_permutes_once_over_zero_state() {
        let input = felts(0..5);
        let expected = MockPerm.permute([pack(&input), N::ZERO, N::ZERO]);
        assert_eq!(TestHasher::new(MockPerm).hash_slice(&input), [expected[0]]);
    }

    /// Empty input permutes zero times, so the digest is the zero state.
    #[test]
    fn empty_input_is_the_zero_digest() {
        assert_eq!(TestHasher::new(MockPerm).hash_slice(&[]), [N::ZERO]);
    }

    /// Base-2^31 little-endian packing: `f_0` occupies the lowest limb.
    #[test]
    fn lane_packing_is_base_2_31_little_endian() {
        let input = felts(0..8);
        let mut expected = N::ZERO;
        let base = N::from_u64(1 << 31);
        for f in input.iter().rev() {
            expected = expected * base + N::from_u32(f.as_canonical_u32());
        }
        assert_eq!(pack(&input), expected);
    }
}
