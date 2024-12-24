//! An implementation of Poseidon2 over BN254.

use crate::{
    compiler::recursion_v2::prelude::*,
    configs::config::FieldGenericConfig,
    primitives::consts::{DIGEST_SIZE, EXTENSION_DEGREE},
    recursion_v2::{air::RecursionPublicValues, runtime::HASH_RATE, types::WIDTH},
};
use p3_baby_bear::BabyBear;
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
    fn poseidon2_permute_v2(&mut self, state: [Felt<FC::F>; WIDTH]) -> [Felt<FC::F>; WIDTH];
    fn poseidon2_hash_v2(&mut self, array: &[Felt<FC::F>]) -> [Felt<FC::F>; DIGEST_SIZE];
    fn poseidon2_compress_v2(
        &mut self,
        input: impl IntoIterator<Item = Felt<FC::F>>,
    ) -> [Felt<FC::F>; DIGEST_SIZE];
    fn ext2felt_v2(&mut self, ext: Ext<FC::F, FC::EF>) -> [Felt<FC::F>; EXTENSION_DEGREE];
    fn commit_public_values_v2(&mut self, public_values: RecursionPublicValues<Felt<FC::F>>);
    fn cycle_tracker_v2_enter(&mut self, name: String);
    fn cycle_tracker_v2_exit(&mut self);
    fn hint_ext_v2(&mut self) -> Ext<FC::F, FC::EF>;
    fn hint_felt_v2(&mut self) -> Felt<FC::F>;
    fn hint_exts_v2(&mut self, len: usize) -> Vec<Ext<FC::F, FC::EF>>;
    fn hint_felts_v2(&mut self, len: usize) -> Vec<Felt<FC::F>>;
}

impl<FC: FieldGenericConfig<F = BabyBear>> CircuitV2Builder<FC> for Builder<FC> {
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

        // Range check the bits to be less than the BabyBear modulus.

        assert!(num_bits <= 31, "num_bits must be less than or equal to 31");

        // If there are less than 31 bits, there is nothing to check.
        if num_bits > 30 {
            // Since BabyBear modulus is 2^31 - 2^27 + 1, if any of the top `4` bits are zero, the
            // number is less than 2^27, and we can stop the iteration. Othwriwse, if all the top
            // `4` bits are '1`, we need to check that all the bottom `27` are '0`

            // Get a flag that is zero if any of the top `4` bits are zero, and one otherwise. We
            // can do this by simply taking their product (which is bitwise AND).
            let are_all_top_bits_one: Felt<_> = self.eval(
                output
                    .iter()
                    .rev()
                    .take(4)
                    .copied()
                    .map(SymbolicFelt::from)
                    .product::<SymbolicFelt<_>>(),
            );

            // Assert that if all the top `4` bits are one, then all the bottom `27` bits are zero.
            for bit in output.iter().take(27).copied() {
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

    /// Applies the Poseidon2 permutation to the given array.
    fn poseidon2_permute_v2(&mut self, array: [Felt<FC::F>; WIDTH]) -> [Felt<FC::F>; WIDTH] {
        let output: [Felt<FC::F>; WIDTH] = core::array::from_fn(|_| self.uninit());
        self.push_op(DslIr::CircuitV2Poseidon2PermuteBabyBear(Box::new((
            output, array,
        ))));
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
        for i in 0..4 {
            let felt = felts[i];
            let monomial: Ext<FC::F, FC::EF> = self.constant(FC::EF::monomial(i));
            reconstructed_ext = self.eval(reconstructed_ext + monomial * felt);
        }

        self.assert_ext_eq(reconstructed_ext, ext);

        felts
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
