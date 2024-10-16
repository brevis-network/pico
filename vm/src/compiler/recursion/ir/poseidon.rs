use super::{Array, Builder, Config, DslIr, Ext, Felt, Usize, Var};
use crate::{
    primitives::consts::DIGEST_SIZE,
    recursion::runtime::{HASH_RATE, PERMUTATION_WIDTH},
};
use p3_field::AbstractField;

impl<CF: Config> Builder<CF> {
    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: [p3_poseidon2::Poseidon2]
    pub fn poseidon2_permute(&mut self, array: &Array<CF, Felt<CF::F>>) -> Array<CF, Felt<CF::F>> {
        let output = match array {
            Array::Fixed(values) => {
                assert_eq!(values.len(), PERMUTATION_WIDTH);
                self.array::<Felt<CF::F>>(Usize::Const(PERMUTATION_WIDTH))
            }
            Array::Dyn(_, len) => self.array::<Felt<CF::F>>(*len),
        };
        self.operations
            .push(DslIr::Poseidon2PermuteBabyBear(Box::new((
                output.clone(),
                array.clone(),
            ))));
        output
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: [p3_poseidon2::Poseidon2]
    pub fn poseidon2_permute_mut(&mut self, array: &Array<CF, Felt<CF::F>>) {
        self.operations
            .push(DslIr::Poseidon2PermuteBabyBear(Box::new((
                array.clone(),
                array.clone(),
            ))));
    }

    /// Applies the Poseidon2 absorb function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    pub fn poseidon2_absorb(
        &mut self,
        p2_hash_and_absorb_num: Var<CF::N>,
        input: &Array<CF, Felt<CF::F>>,
    ) {
        self.operations.push(DslIr::Poseidon2AbsorbBabyBear(
            p2_hash_and_absorb_num,
            input.clone(),
        ));
    }

    /// Applies the Poseidon2 finalize to the given hash number.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    pub fn poseidon2_finalize_mut(
        &mut self,
        p2_hash_num: Var<CF::N>,
        output: &Array<CF, Felt<CF::F>>,
    ) {
        self.operations.push(DslIr::Poseidon2FinalizeBabyBear(
            p2_hash_num,
            output.clone(),
        ));
    }

    /// Applies the Poseidon2 compression function to the given array.
    ///
    /// Reference: [p3_symmetric::TruncatedPermutation]
    pub fn poseidon2_compress(
        &mut self,
        left: &Array<CF, Felt<CF::F>>,
        right: &Array<CF, Felt<CF::F>>,
    ) -> Array<CF, Felt<CF::F>> {
        let mut input = self.dyn_array(PERMUTATION_WIDTH);
        for i in 0..DIGEST_SIZE {
            let a = self.get(left, i);
            let b = self.get(right, i);
            self.set(&mut input, i, a);
            self.set(&mut input, i + DIGEST_SIZE, b);
        }
        self.poseidon2_permute_mut(&input);
        input
    }

    /// Applies the Poseidon2 compression to the given array.
    ///
    /// Reference: [p3_symmetric::TruncatedPermutation]
    pub fn poseidon2_compress_x(
        &mut self,
        result: &mut Array<CF, Felt<CF::F>>,
        left: &Array<CF, Felt<CF::F>>,
        right: &Array<CF, Felt<CF::F>>,
    ) {
        self.operations
            .push(DslIr::Poseidon2CompressBabyBear(Box::new((
                result.clone(),
                left.clone(),
                right.clone(),
            ))));
    }

    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    pub fn poseidon2_hash(&mut self, array: &Array<CF, Felt<CF::F>>) -> Array<CF, Felt<CF::F>> {
        let mut state: Array<CF, Felt<CF::F>> = self.dyn_array(PERMUTATION_WIDTH);

        let break_flag: Var<_> = self.eval(CF::N::zero());
        let last_index: Usize<_> = self.eval(array.len() - 1);
        self.range(0, array.len())
            .step_by(HASH_RATE)
            .for_each(|i, builder| {
                builder.if_eq(break_flag, CF::N::one()).then(|builder| {
                    builder.break_loop();
                });
                // Insert elements of the chunk.
                builder.range(0, HASH_RATE).for_each(|j, builder| {
                    let index: Var<_> = builder.eval(i + j);
                    let element = builder.get(array, index);
                    builder.set_value(&mut state, j, element);
                    builder.if_eq(index, last_index).then(|builder| {
                        builder.assign(break_flag, CF::N::one());
                        builder.break_loop();
                    });
                });

                builder.poseidon2_permute_mut(&state);
            });

        state.truncate(self, Usize::Const(DIGEST_SIZE));
        state
    }

    pub fn poseidon2_hash_x(
        &mut self,
        array: &Array<CF, Array<CF, Felt<CF::F>>>,
    ) -> Array<CF, Felt<CF::F>> {
        self.cycle_tracker("poseidon2-hash");

        let p2_hash_num = self.p2_hash_num;
        let two_power_12: Var<_> = self.eval(CF::N::from_canonical_u32(1 << 12));

        self.range(0, array.len()).for_each(|i, builder| {
            let subarray = builder.get(array, i);
            let p2_hash_and_absorb_num: Var<_> = builder.eval(p2_hash_num * two_power_12 + i);

            builder.poseidon2_absorb(p2_hash_and_absorb_num, &subarray);
        });

        let output: Array<CF, Felt<CF::F>> = self.dyn_array(DIGEST_SIZE);
        self.poseidon2_finalize_mut(self.p2_hash_num, &output);

        self.assign(self.p2_hash_num, self.p2_hash_num + CF::N::one());

        self.cycle_tracker("poseidon2-hash");
        output
    }

    pub fn poseidon2_hash_ext(
        &mut self,
        array: &Array<CF, Array<CF, Ext<CF::F, CF::EF>>>,
    ) -> Array<CF, Felt<CF::F>> {
        self.cycle_tracker("poseidon2-hash-ext");
        let mut state: Array<CF, Felt<CF::F>> = self.dyn_array(PERMUTATION_WIDTH);

        let idx: Var<_> = self.eval(CF::N::zero());
        self.range(0, array.len()).for_each(|i, builder| {
            let subarray = builder.get(array, i);
            builder.range(0, subarray.len()).for_each(|j, builder| {
                let element = builder.get(&subarray, j);
                let felts = builder.ext2felt(element);
                for i in 0..4 {
                    let felt = builder.get(&felts, i);
                    builder.set_value(&mut state, idx, felt);
                    builder.assign(idx, idx + CF::N::one());
                    builder
                        .if_eq(idx, CF::N::from_canonical_usize(HASH_RATE))
                        .then(|builder| {
                            builder.poseidon2_permute_mut(&state);
                            builder.assign(idx, CF::N::zero());
                        });
                }
            });
        });

        self.if_ne(idx, CF::N::zero()).then(|builder| {
            builder.poseidon2_permute_mut(&state);
        });

        state.truncate(self, Usize::Const(DIGEST_SIZE));
        self.cycle_tracker("poseidon2-hash-ext");
        state
    }
}
