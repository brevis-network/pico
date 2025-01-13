//! An implementation of Poseidon2 over BN254.

use crate::{
    compiler::recursion_v2::prelude::*,
    configs::config::FieldGenericConfig,
    machine::{
        field::{FieldBehavior, FieldType},
        septic::{SepticCurve, SepticDigest, SepticExtension},
    },
    primitives::consts::{DIGEST_SIZE, EXTENSION_DEGREE},
    recursion_v2::{air::RecursionPublicValues, runtime::HASH_RATE, types::WIDTH},
};
use itertools::Itertools;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use std::iter::repeat;

pub trait CircuitV2Builder<FC: FieldGenericConfig> {
    fn bits2num_v2_f(
        &mut self,
        bits: impl IntoIterator<Item = Felt<<FC as FieldGenericConfig>::F>>,
    ) -> Felt<FC::F>;
    fn num2bits_v2_f(&mut self, num: Felt<FC::F>, num_bits: usize) -> Vec<Felt<FC::F>>;
    fn exp_reverse_bits_v2(
        &mut self,
        input: Felt<FC::F>,
        power_bits: Vec<Felt<FC::F>>,
    ) -> Felt<FC::F>;
    fn batch_fri(
        &mut self,
        alphas: Vec<Ext<FC::F, FC::EF>>,
        p_at_zs: Vec<Ext<FC::F, FC::EF>>,
        p_at_xs: Vec<Felt<FC::F>>,
    ) -> Ext<FC::F, FC::EF>;
    fn poseidon2_permute_v2(&mut self, state: [Felt<FC::F>; WIDTH]) -> [Felt<FC::F>; WIDTH];
    fn poseidon2_hash_v2(&mut self, array: &[Felt<FC::F>]) -> [Felt<FC::F>; DIGEST_SIZE];
    fn poseidon2_compress_v2(
        &mut self,
        input: impl IntoIterator<Item = Felt<FC::F>>,
    ) -> [Felt<FC::F>; DIGEST_SIZE];
    fn ext2felt_v2(&mut self, ext: Ext<FC::F, FC::EF>) -> [Felt<FC::F>; EXTENSION_DEGREE];
    fn add_curve_v2(
        &mut self,
        point1: SepticCurve<Felt<FC::F>>,
        point2: SepticCurve<Felt<FC::F>>,
    ) -> SepticCurve<Felt<FC::F>>;
    fn assert_digest_zero_v2(&mut self, is_real: Felt<FC::F>, digest: SepticDigest<Felt<FC::F>>);
    fn sum_digest_v2(
        &mut self,
        digests: Vec<SepticDigest<Felt<FC::F>>>,
    ) -> SepticDigest<Felt<FC::F>>;
    fn select_global_cumulative_sum(
        &mut self,
        is_first_shard: Felt<FC::F>,
        vk_digest: SepticDigest<Felt<FC::F>>,
    ) -> SepticDigest<Felt<FC::F>>;
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<FC::F>>);
    fn cycle_tracker_v2_enter(&mut self, name: String);
    fn cycle_tracker_v2_exit(&mut self);
    fn hint_ext_v2(&mut self) -> Ext<FC::F, FC::EF>;
    fn hint_felt_v2(&mut self) -> Felt<FC::F>;
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<FC::F, FC::EF>>;
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<FC::F>>;
}

impl<FC: FieldGenericConfig> CircuitV2Builder<FC> for Builder<FC> {
    fn bits2num_v2_f(
        &mut self,
        bits: impl IntoIterator<Item = Felt<<FC as FieldGenericConfig>::F>>,
    ) -> Felt<<FC as FieldGenericConfig>::F> {
        let mut num: Felt<_> = self.eval(FC::F::ZERO);
        for (i, bit) in bits.into_iter().enumerate() {
            // Add `bit * 2^i` to the sum.
            num = self.eval(num + bit * FC::F::from_wrapped_u32(1 << i));
        }
        num
    }

    /// Converts a felt to bits inside a circuit.
    fn num2bits_v2_f(&mut self, num: Felt<FC::F>, num_bits: usize) -> Vec<Felt<FC::F>> {
        let output = std::iter::from_fn(|| Some(self.uninit()))
            .take(num_bits)
            .collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintBitsF(output.clone(), num));

        let x: SymbolicFelt<_> = output
            .iter()
            .enumerate()
            .map(|(i, &bit)| {
                self.assert_felt_eq(bit * (bit - FC::F::ONE), FC::F::ZERO);
                bit * FC::F::from_wrapped_u32(1 << i)
            })
            .sum();

        // Range check the bits to be less than the field modulus.

        assert!(num_bits <= 31, "num_bits must be less than or equal to 31");

        // If there are less than 31 bits, there is nothing to check.
        if num_bits > 30 {
            let one_start_idx = match FC::F::field_type() {
                FieldType::TypeBabyBear => 3,
                FieldType::TypeKoalaBear => 0,
                _ => unimplemented!("Unsupported field type"),
            };

            // Since BabyBear modulus is 2^31 - 2^27 + 1, if any of the top `4` bits are zero, the
            // number is less than 2^27, and we can stop the iteration. Othwriwse, if all the top
            // `4` bits are '1`, we need to check that all the bottom `27` are '0`

            // Since KoalaBear modulus is 2^31 - 2^24 + 1, if any of the top `7` bits are zero, the
            // number is less than 2^24, and we can stop the iteration. Othwriwse, if all the top
            // `7` bits are '1`, we need to check that all the bottom `24` are '0`

            // Get a flag that is zero if any of the top `4` bits are zero, and one otherwise. We
            // can do this by simply taking their product (which is bitwise AND).
            let are_all_top_bits_one: Felt<_> = self.eval(
                output
                    .iter()
                    .rev()
                    .take(7 - one_start_idx)
                    .copied()
                    .map(SymbolicFelt::from)
                    .product::<SymbolicFelt<_>>(),
            );

            for bit in output.iter().take(24 + one_start_idx).copied() {
                self.assert_felt_eq(bit * are_all_top_bits_one, FC::F::ZERO);
            }
        }

        // Check that the original number matches the bit decomposition.
        self.assert_felt_eq(x, num);

        output
    }

    /// A version of `exp_reverse_bits_len` that uses the ExpReverseBitsLen precompile.
    fn exp_reverse_bits_v2(
        &mut self,
        input: Felt<FC::F>,
        power_bits: Vec<Felt<FC::F>>,
    ) -> Felt<FC::F> {
        let output: Felt<_> = self.uninit();
        self.push_op(DslIr::CircuitV2ExpReverseBits(output, input, power_bits));
        output
    }

    /// batch_fri precompile chip
    fn batch_fri(
        &mut self,
        alphas: Vec<Ext<FC::F, FC::EF>>,
        p_at_zs: Vec<Ext<FC::F, FC::EF>>,
        p_at_xs: Vec<Felt<FC::F>>,
    ) -> Ext<FC::F, FC::EF> {
        let output: Ext<_, _> = self.uninit();
        self.push_op(DslIr::CircuitBatchFRI(Box::new((
            output, alphas, p_at_zs, p_at_xs,
        ))));
        output
    }

    /// Applies the Poseidon2 permutation to the given array.
    fn poseidon2_permute_v2(&mut self, array: [Felt<FC::F>; WIDTH]) -> [Felt<FC::F>; WIDTH] {
        let output: [Felt<FC::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.push_op(match FC::F::field_type() {
            FieldType::TypeBabyBear => {
                DslIr::CircuitV2Poseidon2PermuteBabyBear(Box::new((output, array)))
            }
            FieldType::TypeKoalaBear => {
                DslIr::CircuitV2Poseidon2PermuteKoalaBear(Box::new((output, array)))
            }
            _ => unimplemented!("Poseidon2 permutation not implemented for this field"),
        });
        output
    }

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash_v2(&mut self, input: &[Felt<FC::F>]) -> [Felt<FC::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| self.eval(FC::F::ZERO));
        for input_chunk in input.chunks(HASH_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = self.poseidon2_permute_v2(state);
        }
        let state: [Felt<FC::F>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        state
    }

    /// Applies the Poseidon2 compression function to the given array.
    ///
    /// Reference: [p3_symmetric::TruncatedPermutation]
    fn poseidon2_compress_v2(
        &mut self,
        input: impl IntoIterator<Item = Felt<FC::F>>,
    ) -> [Felt<FC::F>; DIGEST_SIZE] {
        // debug_assert!(DIGEST_SIZE * N <= WIDTH);
        let mut pre_iter = input.into_iter().chain(repeat(self.eval(FC::F::default())));
        let pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
        let post = self.poseidon2_permute_v2(pre);
        let post: [Felt<FC::F>; DIGEST_SIZE] = post[..DIGEST_SIZE].try_into().unwrap();
        post
    }

    /// Decomposes an ext into its felt coordinates.
    fn ext2felt_v2(&mut self, ext: Ext<FC::F, FC::EF>) -> [Felt<FC::F>; EXTENSION_DEGREE] {
        let felts = core::array::from_fn(|_| self.uninit());
        self.push_op(DslIr::CircuitExt2Felt(felts, ext));
        // Verify that the decomposed extension element is correct.
        let mut reconstructed_ext: Ext<FC::F, FC::EF> = self.constant(FC::EF::ZERO);
        for i in 0..FC::EF::D {
            let felt = felts[i];
            let monomial: Ext<FC::F, FC::EF> = self.constant(FC::EF::monomial(i));
            reconstructed_ext = self.eval(reconstructed_ext + monomial * felt);
        }

        self.assert_ext_eq(reconstructed_ext, ext);

        felts
    }

    /// Adds two septic elliptic curve points.
    fn add_curve_v2(
        &mut self,
        point1: SepticCurve<Felt<FC::F>>,
        point2: SepticCurve<Felt<FC::F>>,
    ) -> SepticCurve<Felt<FC::F>> {
        let point_sum_x: [Felt<FC::F>; 7] = core::array::from_fn(|_| self.uninit());
        let point_sum_y: [Felt<FC::F>; 7] = core::array::from_fn(|_| self.uninit());
        let point = SepticCurve {
            x: SepticExtension(point_sum_x),
            y: SepticExtension(point_sum_y),
        };
        self.push_op(DslIr::CircuitV2HintAddCurve(Box::new((
            point, point1, point2,
        ))));

        let point1_symbolic = SepticCurve::convert(point1, |x| x.into());
        let point2_symbolic = SepticCurve::convert(point2, |x| x.into());
        let point_symbolic = SepticCurve::convert(point, |x| x.into());

        let sum_checker_x = SepticCurve::<SymbolicFelt<FC::F>>::sum_checker_x(
            point1_symbolic,
            point2_symbolic,
            point_symbolic,
        );

        let sum_checker_y = SepticCurve::<SymbolicFelt<FC::F>>::sum_checker_y(
            point1_symbolic,
            point2_symbolic,
            point_symbolic,
        );

        for limb in sum_checker_x.0 {
            self.assert_felt_eq(limb, FC::F::ZERO);
        }

        for limb in sum_checker_y.0 {
            self.assert_felt_eq(limb, FC::F::ZERO);
        }

        point
    }

    /// Asserts that the SepticDigest is zero.
    fn assert_digest_zero_v2(&mut self, is_real: Felt<FC::F>, digest: SepticDigest<Felt<FC::F>>) {
        let zero = SepticDigest::<SymbolicFelt<FC::F>>::zero();
        for (digest_limb_x, zero_limb_x) in digest.0.x.0.into_iter().zip_eq(zero.0.x.0.into_iter())
        {
            self.assert_felt_eq(is_real * digest_limb_x, is_real * zero_limb_x);
        }
        for (digest_limb_y, zero_limb_y) in digest.0.y.0.into_iter().zip_eq(zero.0.y.0.into_iter())
        {
            self.assert_felt_eq(is_real * digest_limb_y, is_real * zero_limb_y);
        }
    }

    // Sums the digests into one.
    fn sum_digest_v2(
        &mut self,
        digests: Vec<SepticDigest<Felt<FC::F>>>,
    ) -> SepticDigest<Felt<FC::F>> {
        let mut convert_to_felt =
            |point: SepticCurve<FC::F>| SepticCurve::convert(point, |value| self.eval(value));

        let start = convert_to_felt(SepticDigest::starting_digest().0);
        let zero_digest = convert_to_felt(SepticDigest::zero().0);

        if digests.is_empty() {
            return SepticDigest(zero_digest);
        }

        let neg_start = convert_to_felt(SepticDigest::starting_digest().0.neg());
        let neg_zero_digest = convert_to_felt(SepticDigest::zero().0.neg());

        let mut ret = start;
        for (i, digest) in digests.clone().into_iter().enumerate() {
            ret = self.add_curve_v2(ret, digest.0);
            if i != digests.len() - 1 {
                ret = self.add_curve_v2(ret, neg_zero_digest)
            }
        }
        SepticDigest(self.add_curve_v2(ret, neg_start))
    }

    /// Returns the zero digest when `flag_first_chunk` is zero, and returns the `digest` when `flag_first_chunk` is one.
    fn select_global_cumulative_sum(
        &mut self,
        is_first_shard: Felt<FC::F>,
        vk_digest: SepticDigest<Felt<FC::F>>,
    ) -> SepticDigest<Felt<FC::F>> {
        let zero = SepticDigest::<SymbolicFelt<FC::F>>::zero();
        let one: Felt<FC::F> = self.constant(FC::F::ONE);
        let x = SepticExtension(core::array::from_fn(|i| {
            self.eval(is_first_shard * vk_digest.0.x.0[i] + (one - is_first_shard) * zero.0.x.0[i])
        }));
        let y = SepticExtension(core::array::from_fn(|i| {
            self.eval(is_first_shard * vk_digest.0.y.0[i] + (one - is_first_shard) * zero.0.y.0[i])
        }));
        SepticDigest(SepticCurve { x, y })
    }

    // Commits public values.
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<FC::F>>) {
        self.push_op(DslIr::CircuitV2CommitPublicValues(Box::new(public_values)));
    }

    fn cycle_tracker_v2_enter(&mut self, name: String) {
        self.push_op(DslIr::CycleTrackerV2Enter(name));
    }

    fn cycle_tracker_v2_exit(&mut self) {
        self.push_op(DslIr::CycleTrackerV2Exit);
    }

    /// Hint a single felt.
    fn hint_felt_v2(&mut self) -> Felt<FC::F> {
        self.hint_felts_v2(1)[0]
    }

    /// Hint a single ext.
    fn hint_ext_v2(&mut self) -> Ext<FC::F, FC::EF> {
        self.hint_exts_v2(1)[0]
    }

    /// Hint a vector of felts.
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<FC::F>> {
        let arr = std::iter::from_fn(|| Some(self.uninit()))
            .take(len)
            .collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintFelts(arr.clone()));
        arr
    }

    /// Hint a vector of exts.
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<FC::F, FC::EF>> {
        let arr = std::iter::from_fn(|| Some(self.uninit()))
            .take(len)
            .collect::<Vec<_>>();
        self.push_op(DslIr::CircuitV2HintExts(arr.clone()));
        arr
    }
}
