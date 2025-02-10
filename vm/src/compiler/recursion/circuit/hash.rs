use super::{builder::CircuitBuilder, challenger::reduce_32, config::CircuitConfig};
use crate::{
    compiler::recursion::ir::{Builder, DslIr, Felt, Var},
    configs::{
        config::{FieldGenericConfig, Val},
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2,
            kb_bn254_poseidon2::KoalaBearBn254Poseidon2, kb_poseidon2::KoalaBearPoseidon2,
        },
    },
    machine::field::{FieldBehavior, FieldType},
    primitives::{
        consts::{DIGEST_SIZE, MULTI_FIELD_CHALLENGER_WIDTH, PERMUTATION_RATE, PERMUTATION_WIDTH},
        pico_poseidon2bb_init, pico_poseidon2bn254_init, pico_poseidon2kb_init,
    },
};
use itertools::Itertools;
use p3_bn254_fr::Bn254Fr;
use p3_field::{Field, FieldAlgebra};
use p3_symmetric::Permutation;
use std::{
    fmt::Debug,
    iter::{repeat, zip},
};

pub trait FieldHasher<F: Field> {
    type Digest: Copy + Default + Eq + Ord + Copy + Debug + Send + Sync;

    fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest;
}

pub trait Posedion2FieldHasherVariable<CC: CircuitConfig> {
    fn poseidon2_permute(
        builder: &mut Builder<CC>,
        state: [Felt<CC::F>; PERMUTATION_WIDTH],
    ) -> [Felt<CC::F>; PERMUTATION_WIDTH];

    /// Applies the Poseidon2 hash function to the given array.
    ///
    /// Reference: [p3_symmetric::PaddingFreeSponge]
    fn poseidon2_hash(
        builder: &mut Builder<CC>,
        input: &[Felt<CC::F>],
    ) -> [Felt<CC::F>; DIGEST_SIZE] {
        // static_assert(RATE < WIDTH)
        let mut state = core::array::from_fn(|_| builder.eval(CC::F::ZERO));
        for input_chunk in input.chunks(PERMUTATION_RATE) {
            state[..input_chunk.len()].copy_from_slice(input_chunk);
            state = Self::poseidon2_permute(builder, state);
        }
        let digest: [Felt<CC::F>; DIGEST_SIZE] = state[..DIGEST_SIZE].try_into().unwrap();
        digest
    }
}

pub trait FieldHasherVariable<CC: CircuitConfig>: FieldHasher<CC::F> {
    type DigestVariable: Clone + Copy;

    fn hash(builder: &mut Builder<CC>, input: &[Felt<CC::F>]) -> Self::DigestVariable;

    fn compress(
        builder: &mut Builder<CC>,
        input: [Self::DigestVariable; 2],
    ) -> Self::DigestVariable;

    fn assert_digest_eq(
        builder: &mut Builder<CC>,
        a: Self::DigestVariable,
        b: Self::DigestVariable,
    );

    // Encountered many issues trying to make the following two parametrically polymorphic.
    fn select_chain_digest(
        builder: &mut Builder<CC>,
        should_swap: CC::Bit,
        input: [Self::DigestVariable; 2],
    ) -> [Self::DigestVariable; 2];

    fn print_digest(builder: &mut Builder<CC>, digest: Self::DigestVariable);
}

macro_rules! impl_hash_related {
    ($recur_sc:ident, $hash_init:ident) => {
        impl FieldHasher<Val<$recur_sc>> for $recur_sc {
            type Digest = [Val<$recur_sc>; DIGEST_SIZE];

            fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
                let mut pre_iter = input
                    .into_iter()
                    .flatten()
                    .chain(repeat(Val::<$recur_sc>::ZERO));
                let mut pre = core::array::from_fn(move |_| pre_iter.next().unwrap());
                ($hash_init()).permute_mut(&mut pre);
                pre[..DIGEST_SIZE].try_into().unwrap()
            }
        }

        impl<CC: CircuitConfig<F = Val<$recur_sc>>> Posedion2FieldHasherVariable<CC> for $recur_sc {
            fn poseidon2_permute(
                builder: &mut Builder<CC>,
                input: [Felt<<CC>::F>; PERMUTATION_WIDTH],
            ) -> [Felt<<CC>::F>; PERMUTATION_WIDTH] {
                builder.poseidon2_permute(input)
            }
        }

        impl<CC: CircuitConfig<F = Val<$recur_sc>, Bit = Felt<Val<$recur_sc>>>>
            FieldHasherVariable<CC> for $recur_sc
        {
            type DigestVariable = [Felt<Val<$recur_sc>>; DIGEST_SIZE];

            fn hash(
                builder: &mut Builder<CC>,
                input: &[Felt<<CC as FieldGenericConfig>::F>],
            ) -> Self::DigestVariable {
                <Self as Posedion2FieldHasherVariable<CC>>::poseidon2_hash(builder, input)
            }

            fn compress(
                builder: &mut Builder<CC>,
                input: [Self::DigestVariable; 2],
            ) -> Self::DigestVariable {
                builder.poseidon2_compress(input.into_iter().flatten())
            }

            fn assert_digest_eq(
                builder: &mut Builder<CC>,
                a: Self::DigestVariable,
                b: Self::DigestVariable,
            ) {
                zip(a, b).for_each(|(e1, e2)| builder.assert_felt_eq(e1, e2));
            }

            fn select_chain_digest(
                builder: &mut Builder<CC>,
                should_swap: <CC as CircuitConfig>::Bit,
                input: [Self::DigestVariable; 2],
            ) -> [Self::DigestVariable; 2] {
                let result0: [Felt<CC::F>; DIGEST_SIZE] =
                    core::array::from_fn(|_| builder.uninit());
                let result1: [Felt<CC::F>; DIGEST_SIZE] =
                    core::array::from_fn(|_| builder.uninit());

                (0..DIGEST_SIZE).for_each(|i| {
                    builder.push_op(DslIr::Select(
                        should_swap,
                        result0[i],
                        result1[i],
                        input[0][i],
                        input[1][i],
                    ));
                });

                [result0, result1]
            }

            fn print_digest(builder: &mut Builder<CC>, digest: Self::DigestVariable) {
                for d in digest.iter() {
                    builder.print_f(*d);
                }
            }
        }
    };
}

impl_hash_related!(BabyBearPoseidon2, pico_poseidon2bb_init);
impl_hash_related!(KoalaBearPoseidon2, pico_poseidon2kb_init);

pub const BN254_DIGEST_SIZE: usize = 1;

macro_rules! impl_embed_hash_related {
    ($embed_sc:ident) => {
        impl<CC: CircuitConfig> Posedion2FieldHasherVariable<CC> for $embed_sc {
            fn poseidon2_permute(
                builder: &mut Builder<CC>,
                state: [Felt<<CC>::F>; PERMUTATION_WIDTH],
            ) -> [Felt<<CC>::F>; PERMUTATION_WIDTH] {
                let state: [Felt<_>; PERMUTATION_WIDTH] = state.map(|x| builder.eval(x));
                match CC::F::field_type() {
                    FieldType::TypeBabyBear => {
                        builder.push_op(DslIr::ConstraintPoseidon2BabyBear(Box::new(state)));
                    }
                    FieldType::TypeKoalaBear => {
                        builder.push_op(DslIr::ConstraintPoseidon2KoalaBear(Box::new(state)));
                    }
                    _ => unreachable!(),
                }
                state
            }
        }

        impl FieldHasher<Val<$embed_sc>> for $embed_sc {
            type Digest = [Bn254Fr; BN254_DIGEST_SIZE];

            fn constant_compress(input: [Self::Digest; 2]) -> Self::Digest {
                let mut state = [input[0][0], input[1][0], Bn254Fr::ZERO];
                pico_poseidon2bn254_init().permute_mut(&mut state);
                [state[0]; BN254_DIGEST_SIZE]
            }
        }

        impl<CC: CircuitConfig<F = Val<$embed_sc>, N = Bn254Fr, Bit = Var<Bn254Fr>>>
            FieldHasherVariable<CC> for $embed_sc
        {
            type DigestVariable = [Var<Bn254Fr>; BN254_DIGEST_SIZE];

            fn hash(
                builder: &mut Builder<CC>,
                input: &[Felt<<CC as FieldGenericConfig>::F>],
            ) -> Self::DigestVariable {
                assert!(CC::N::bits() == p3_bn254_fr::Bn254Fr::bits());
                assert!(CC::F::bits() == Val::<$embed_sc>::bits());
                let num_f_elms = CC::N::bits() / CC::F::bits();
                let mut state: [Var<CC::N>; MULTI_FIELD_CHALLENGER_WIDTH] = [
                    builder.eval(CC::N::ZERO),
                    builder.eval(CC::N::ZERO),
                    builder.eval(CC::N::ZERO),
                ];
                for block_chunk in &input.iter().chunks(PERMUTATION_WIDTH) {
                    for (chunk_id, chunk) in
                        (&block_chunk.chunks(num_f_elms)).into_iter().enumerate()
                    {
                        let chunk = chunk.copied().collect::<Vec<_>>();
                        state[chunk_id] = reduce_32(builder, chunk.as_slice());
                    }
                    builder.push_op(DslIr::CircuitPoseidon2Permute(state))
                }

                [state[0]; BN254_DIGEST_SIZE]
            }

            fn compress(
                builder: &mut Builder<CC>,
                input: [Self::DigestVariable; 2],
            ) -> Self::DigestVariable {
                let state: [Var<CC::N>; MULTI_FIELD_CHALLENGER_WIDTH] = [
                    builder.eval(input[0][0]),
                    builder.eval(input[1][0]),
                    builder.eval(CC::N::ZERO),
                ];
                builder.push_op(DslIr::CircuitPoseidon2Permute(state));
                [state[0]; BN254_DIGEST_SIZE]
            }

            fn assert_digest_eq(
                builder: &mut Builder<CC>,
                a: Self::DigestVariable,
                b: Self::DigestVariable,
            ) {
                zip(a, b).for_each(|(e1, e2)| builder.assert_var_eq(e1, e2));
            }

            fn select_chain_digest(
                builder: &mut Builder<CC>,
                should_swap: <CC as CircuitConfig>::Bit,
                input: [Self::DigestVariable; 2],
            ) -> [Self::DigestVariable; 2] {
                let result0: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
                    let result = builder.uninit();
                    builder.push_op(DslIr::CircuitSelectV(
                        should_swap,
                        input[1][j],
                        input[0][j],
                        result,
                    ));
                    result
                });
                let result1: [Var<_>; BN254_DIGEST_SIZE] = core::array::from_fn(|j| {
                    let result = builder.uninit();
                    builder.push_op(DslIr::CircuitSelectV(
                        should_swap,
                        input[0][j],
                        input[1][j],
                        result,
                    ));
                    result
                });

                [result0, result1]
            }

            fn print_digest(builder: &mut Builder<CC>, digest: Self::DigestVariable) {
                for d in digest.iter() {
                    builder.print_v(*d);
                }
            }
        }
    };
}

impl_embed_hash_related!(BabyBearBn254Poseidon2);
impl_embed_hash_related!(KoalaBearBn254Poseidon2);
