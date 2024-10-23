use super::{Array, Builder, DslIr, Ext, Felt, Usize, Var};
use crate::{
    configs::config::FieldGenericConfig,
    primitives::consts::DIGEST_SIZE,
    recursion::runtime::{HASH_RATE, PERMUTATION_WIDTH},
};
use p3_field::AbstractField;

impl<RC: FieldGenericConfig> Builder<RC> {
    /// Applies the Poseidon2 permutation to the given array.
    ///
    /// Reference: [p3_poseidon2::Poseidon2]
    pub fn poseidon2_permute(&mut self, array: &Array<RC, Felt<RC::F>>) -> Array<RC, Felt<RC::F>> {
        let output = match array {
            Array::Fixed(values) => {
                assert_eq!(values.len(), PERMUTATION_WIDTH);
                self.array::<Felt<RC::F>>(Usize::Const(PERMUTATION_WIDTH))
            }
            Array::Dyn(_, len) => self.array::<Felt<RC::F>>(*len),
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
    pub fn poseidon2_permute_mut(&mut self, array: &Array<RC, Felt<RC::F>>) {
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
        p2_hash_and_absorb_num: Var<RC::N>,
        input: &Array<RC, Felt<RC::F>>,
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
        p2_hash_num: Var<RC::N>,
        output: &Array<RC, Felt<RC::F>>,
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
        left: &Array<RC, Felt<RC::F>>,
        right: &Array<RC, Felt<RC::F>>,
    ) -> Array<RC, Felt<RC::F>> {
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
        result: &mut Array<RC, Felt<RC::F>>,
        left: &Array<RC, Felt<RC::F>>,
        right: &Array<RC, Felt<RC::F>>,
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
    pub fn poseidon2_hash(&mut self, array: &Array<RC, Felt<RC::F>>) -> Array<RC, Felt<RC::F>> {
        let mut state: Array<RC, Felt<RC::F>> = self.dyn_array(PERMUTATION_WIDTH);

        let break_flag: Var<_> = self.eval(RC::N::zero());
        let last_index: Usize<_> = self.eval(array.len() - 1);
        self.range(0, array.len())
            .step_by(HASH_RATE)
            .for_each(|i, builder| {
                builder.if_eq(break_flag, RC::N::one()).then(|builder| {
                    builder.break_loop();
                });
                // Insert elements of the chunk.
                builder.range(0, HASH_RATE).for_each(|j, builder| {
                    let index: Var<_> = builder.eval(i + j);
                    let element = builder.get(array, index);
                    builder.set_value(&mut state, j, element);
                    builder.if_eq(index, last_index).then(|builder| {
                        builder.assign(break_flag, RC::N::one());
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
        array: &Array<RC, Array<RC, Felt<RC::F>>>,
    ) -> Array<RC, Felt<RC::F>> {
        self.cycle_tracker("poseidon2-hash");

        let p2_hash_num = self.p2_hash_num;
        let two_power_12: Var<_> = self.eval(RC::N::from_canonical_u32(1 << 12));

        self.range(0, array.len()).for_each(|i, builder| {
            let subarray = builder.get(array, i);
            let p2_hash_and_absorb_num: Var<_> = builder.eval(p2_hash_num * two_power_12 + i);

            builder.poseidon2_absorb(p2_hash_and_absorb_num, &subarray);
        });

        let output: Array<RC, Felt<RC::F>> = self.dyn_array(DIGEST_SIZE);
        self.poseidon2_finalize_mut(self.p2_hash_num, &output);

        self.assign(self.p2_hash_num, self.p2_hash_num + RC::N::one());

        self.cycle_tracker("poseidon2-hash");
        output
    }

    pub fn poseidon2_hash_ext(
        &mut self,
        array: &Array<RC, Array<RC, Ext<RC::F, RC::EF>>>,
    ) -> Array<RC, Felt<RC::F>> {
        self.cycle_tracker("poseidon2-hash-ext");
        let mut state: Array<RC, Felt<RC::F>> = self.dyn_array(PERMUTATION_WIDTH);

        let idx: Var<_> = self.eval(RC::N::zero());
        self.range(0, array.len()).for_each(|i, builder| {
            let subarray = builder.get(array, i);
            builder.range(0, subarray.len()).for_each(|j, builder| {
                let element = builder.get(&subarray, j);
                let felts = builder.ext2felt(element);
                for i in 0..4 {
                    let felt = builder.get(&felts, i);
                    builder.set_value(&mut state, idx, felt);
                    builder.assign(idx, idx + RC::N::one());
                    builder
                        .if_eq(idx, RC::N::from_canonical_usize(HASH_RATE))
                        .then(|builder| {
                            builder.poseidon2_permute_mut(&state);
                            builder.assign(idx, RC::N::zero());
                        });
                }
            });
        });

        self.if_ne(idx, RC::N::zero()).then(|builder| {
            builder.poseidon2_permute_mut(&state);
        });

        state.truncate(self, Usize::Const(DIGEST_SIZE));
        self.cycle_tracker("poseidon2-hash-ext");
        state
    }
}
