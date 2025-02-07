//TODO: reorg config

use super::{
    builder::CircuitBuilder,
    challenger::{
        CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
        MultiField32ChallengerVariable, SpongeChallengerShape,
    },
    hash::{FieldHasherVariable, Posedion2FieldHasherVariable},
    utils::{felt_bytes_to_bn254_var, felts_to_bn254_var, words_to_bytes},
};
use crate::{
    compiler::recursion::{
        ir::{Builder, Ext, Felt, Var, Variable},
        prelude::DslIr,
    },
    configs::config::{FieldGenericConfig, SimpleFriConfig, StarkGenericConfig, Val},
    emulator::recursion::public_values::RecursionPublicValues,
    instances::configs::{embed_config, embed_kb_config, recur_config, recur_kb_config},
    primitives::consts::EXTENSION_DEGREE,
};
use itertools::izip;
use p3_bn254_fr::Bn254Fr;
use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_field::FieldAlgebra;
use p3_fri::FriConfig;
use p3_matrix::dense::RowMajorMatrix;
use std::iter::{repeat, zip};

pub type PcsConfig<CC> = FriConfig<
    ExtensionMmcs<
        <CC as StarkGenericConfig>::Val,
        <CC as StarkGenericConfig>::Challenge,
        <CC as FieldFriConfig>::ValMmcs,
    >,
>;

pub type Digest<CC, SC> = <SC as FieldHasherVariable<CC>>::DigestVariable;

pub type FriMmcs<CC> = ExtensionMmcs<
    <CC as StarkGenericConfig>::Val,
    <CC as StarkGenericConfig>::Challenge,
    <CC as FieldFriConfig>::ValMmcs,
>;

pub trait FieldFriConfig: StarkGenericConfig {
    type ValMmcs: Mmcs<Self::Val, ProverData<RowMajorMatrix<Self::Val>> = Self::RowMajorProverData>
        + Send
        + Sync;
    type RowMajorProverData: Clone + Send + Sync;
    type FriChallenger: CanObserve<<Self::ValMmcs as Mmcs<Self::Val>>::Commitment>
        + CanSample<Self::Challenge>
        + GrindingChallenger<Witness = Self::Val>
        + FieldChallenger<Self::Val>;

    fn fri_config(&self) -> &SimpleFriConfig;

    fn challenger_shape(challenger: &Self::FriChallenger) -> SpongeChallengerShape;
}

pub trait FieldFriConfigVariable<CC: CircuitConfig>:
    FieldFriConfig + FieldHasherVariable<CC> + Posedion2FieldHasherVariable<CC>
{
    type FriChallengerVariable: FieldChallengerVariable<CC, <CC as CircuitConfig>::Bit>
        + CanObserveVariable<CC, <Self as FieldHasherVariable<CC>>::DigestVariable>
        + CanCopyChallenger<CC>;

    /// Get a new challenger corresponding to the given config.
    fn challenger_variable(&self, builder: &mut Builder<CC>) -> Self::FriChallengerVariable;

    fn commit_recursion_public_values(
        builder: &mut Builder<CC>,
        public_values: RecursionPublicValues<Felt<CC::F>>,
    );
}

pub trait CircuitConfig: FieldGenericConfig {
    type Bit: Copy + Variable<Self>;

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit;

    fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F>;

    fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit);

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
    ) -> [Felt<<Self as FieldGenericConfig>::F>; EXTENSION_DEGREE];

    fn exp_reverse_bits(
        builder: &mut Builder<Self>,
        input: Felt<<Self as FieldGenericConfig>::F>,
        power_bits: Vec<Self::Bit>,
    ) -> Felt<<Self as FieldGenericConfig>::F>;

    /// Exponentiates a felt x to a list of bits in little endian. Uses precomputed powers
    /// of x.
    fn exp_f_bits_precomputed(
        builder: &mut Builder<Self>,
        power_bits: &[Self::Bit],
        two_adic_powers_of_x: &[Felt<Self::F>],
    ) -> Felt<Self::F>;

    fn batch_fri(
        builder: &mut Builder<Self>,
        alpha_pows: Vec<Ext<Self::F, Self::EF>>,
        p_at_zs: Vec<Ext<Self::F, Self::EF>>,
        p_at_xs: Vec<Felt<Self::F>>,
    ) -> Ext<Self::F, Self::EF>;

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as FieldGenericConfig>::F>,
        num_bits: usize,
    ) -> Vec<Self::Bit>;

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Self::Bit>,
    ) -> Felt<<Self as FieldGenericConfig>::F>;

    #[allow(clippy::type_complexity)]
    fn select_chain_f(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>> + Clone,
        second: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>> + Clone,
    ) -> Vec<Felt<<Self as FieldGenericConfig>::F>>;

    #[allow(clippy::type_complexity)]
    fn select_chain_ef(
        builder: &mut Builder<Self>,
        should_swap: Self::Bit,
        first: impl IntoIterator<
                Item = Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
            > + Clone,
        second: impl IntoIterator<
                Item = Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
            > + Clone,
    ) -> Vec<Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>>;

    fn range_check_felt(builder: &mut Builder<Self>, value: Felt<Self::F>, num_bits: usize) {
        let bits = Self::num2bits(builder, value, 31);
        for bit in bits.into_iter().skip(num_bits) {
            Self::assert_bit_zero(builder, bit);
        }
    }
}

macro_rules! impl_circuit_config_and_fri_variable {
    ($mod_name:ident) => {
        impl CircuitConfig for $mod_name::FieldConfig {
            type Bit = Felt<<Self as FieldGenericConfig>::F>;

            fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
                builder.assert_felt_eq(bit, Self::F::ZERO);
            }

            fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
                builder.hint_felt()
            }

            fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F> {
                builder.hint_felt()
            }

            fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF> {
                builder.hint_ext()
            }

            fn ext2felt(
                builder: &mut Builder<Self>,
                ext: Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
            ) -> [Felt<<Self as FieldGenericConfig>::F>; EXTENSION_DEGREE] {
                builder.ext2felt(ext)
            }

            fn num2bits(
                builder: &mut Builder<Self>,
                num: Felt<<Self as FieldGenericConfig>::F>,
                num_bits: usize,
            ) -> Vec<Felt<<Self as FieldGenericConfig>::F>> {
                builder.num2bits_f(num, num_bits)
            }

            fn bits2num(
                builder: &mut Builder<Self>,
                bits: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>>,
            ) -> Felt<<Self as FieldGenericConfig>::F> {
                builder.bits2num_f(bits)
            }

            fn select_chain_f(
                builder: &mut Builder<Self>,
                should_swap: Self::Bit,
                first: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>> + Clone,
                second: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>> + Clone,
            ) -> Vec<Felt<<Self as FieldGenericConfig>::F>> {
                let one: Felt<_> = builder.constant(Self::F::ONE);
                let should_not_swap: Felt<_> = builder.eval(one - should_swap);

                let id_branch = first.clone().into_iter().chain(second.clone());
                let swap_branch = second.into_iter().chain(first);
                zip(
                    zip(id_branch, swap_branch),
                    zip(repeat(should_not_swap), repeat(should_swap)),
                )
                .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
                .collect()
            }

            fn select_chain_ef(
                builder: &mut Builder<Self>,
                should_swap: Self::Bit,
                first: impl IntoIterator<
                        Item = Ext<
                            <Self as FieldGenericConfig>::F,
                            <Self as FieldGenericConfig>::EF,
                        >,
                    > + Clone,
                second: impl IntoIterator<
                        Item = Ext<
                            <Self as FieldGenericConfig>::F,
                            <Self as FieldGenericConfig>::EF,
                        >,
                    > + Clone,
            ) -> Vec<Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>> {
                let one: Felt<_> = builder.constant(Self::F::ONE);
                let should_not_swap: Felt<_> = builder.eval(one - should_swap);

                let id_branch = first.clone().into_iter().chain(second.clone());
                let swap_branch = second.into_iter().chain(first);
                zip(
                    zip(id_branch, swap_branch),
                    zip(repeat(should_not_swap), repeat(should_swap)),
                )
                .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_v * id_c + sw_v * sw_c))
                .collect()
            }

            fn exp_f_bits_precomputed(
                builder: &mut Builder<Self>,
                power_bits: &[Self::Bit],
                two_adic_powers_of_x: &[Felt<Self::F>],
            ) -> Felt<Self::F> {
                Self::exp_reverse_bits(
                    builder,
                    two_adic_powers_of_x[0],
                    power_bits.iter().rev().copied().collect(),
                )
            }

            fn exp_reverse_bits(
                builder: &mut Builder<Self>,
                input: Felt<<Self as FieldGenericConfig>::F>,
                power_bits: Vec<Felt<<Self as FieldGenericConfig>::F>>,
            ) -> Felt<<Self as FieldGenericConfig>::F> {
                builder.exp_reverse_bits(input, power_bits)
            }

            fn batch_fri(
                builder: &mut Builder<Self>,
                alpha_pows: Vec<
                    Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
                >,
                p_at_zs: Vec<
                    Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
                >,
                p_at_xs: Vec<Felt<<Self as FieldGenericConfig>::F>>,
            ) -> Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF> {
                builder.batch_fri(alpha_pows, p_at_zs, p_at_xs)
            }
        }

        impl FieldFriConfig for $mod_name::StarkConfig {
            type ValMmcs = $mod_name::SC_ValMmcs;
            type FriChallenger = <Self as StarkGenericConfig>::Challenger;
            type RowMajorProverData =
                <$mod_name::SC_ValMmcs as Mmcs<$mod_name::SC_Val>>::ProverData<
                    RowMajorMatrix<$mod_name::SC_Val>,
                >;

            fn fri_config(&self) -> &SimpleFriConfig {
                self.fri_config()
            }

            fn challenger_shape(challenger: &Self::FriChallenger) -> SpongeChallengerShape {
                SpongeChallengerShape {
                    input_buffer_len: challenger.input_buffer.len(),
                    output_buffer_len: challenger.output_buffer.len(),
                }
            }
        }

        impl<CC: CircuitConfig<F = $mod_name::SC_Val, Bit = Felt<$mod_name::SC_Val>>>
            FieldFriConfigVariable<CC> for $mod_name::StarkConfig
        {
            type FriChallengerVariable = DuplexChallengerVariable<CC>;

            fn challenger_variable(
                &self,
                builder: &mut Builder<CC>,
            ) -> Self::FriChallengerVariable {
                DuplexChallengerVariable::new(builder)
            }

            fn commit_recursion_public_values(
                builder: &mut Builder<CC>,
                public_values: RecursionPublicValues<Felt<<CC>::F>>,
            ) {
                builder.commit_public_values(public_values);
            }
        }
    };
}

impl_circuit_config_and_fri_variable!(recur_config);
impl_circuit_config_and_fri_variable!(recur_kb_config);

macro_rules! impl_fri_field_config {
    ($mod_name:ident) => {
        impl FieldFriConfig for $mod_name::StarkConfig {
            type ValMmcs = $mod_name::SC_ValMmcs;
            type FriChallenger = <Self as StarkGenericConfig>::Challenger;

            type RowMajorProverData = <$mod_name::SC_ValMmcs as Mmcs<
                Val<$mod_name::StarkConfig>,
            >>::ProverData<RowMajorMatrix<Val<$mod_name::StarkConfig>>>;

            fn fri_config(&self) -> &SimpleFriConfig {
                self.fri_config()
            }

            fn challenger_shape(_challenger: &Self::FriChallenger) -> SpongeChallengerShape {
                unimplemented!("Shape not supported for outer fri challenger");
            }
        }
    };
}

impl_fri_field_config!(embed_config);
impl_fri_field_config!(embed_kb_config);

macro_rules! impl_field_fri_config_variable {
    ($mod_name:ident) => {
        impl<
                C: CircuitConfig<F = Val<$mod_name::StarkConfig>, N = Bn254Fr, Bit = Var<Bn254Fr>>,
            > FieldFriConfigVariable<C> for $mod_name::StarkConfig
        {
            type FriChallengerVariable = MultiField32ChallengerVariable<C>;

            fn challenger_variable(&self, builder: &mut Builder<C>) -> Self::FriChallengerVariable {
                MultiField32ChallengerVariable::new(builder)
            }

            fn commit_recursion_public_values(
                builder: &mut Builder<C>,
                public_values: RecursionPublicValues<Felt<<C>::F>>,
            ) {
                let committed_values_digest_bytes_felts: [Felt<_>; 32] =
                    words_to_bytes(&public_values.committed_value_digest)
                        .try_into()
                        .unwrap();
                let committed_values_digest_bytes: Var<_> =
                    felt_bytes_to_bn254_var(builder, &committed_values_digest_bytes_felts);
                builder.commit_committed_values_digest_circuit(committed_values_digest_bytes);

                let vkey_hash = felts_to_bn254_var(builder, &public_values.riscv_vk_digest);
                builder.commit_vkey_hash_circuit(vkey_hash);
            }
        }
    };
}

impl_field_fri_config_variable!(embed_config);
impl_field_fri_config_variable!(embed_kb_config);

macro_rules! impl_embed_circuit_config {
    ($mod_name:ident) => {
        impl CircuitConfig for $mod_name::FieldConfig {
            type Bit = Var<<Self as FieldGenericConfig>::N>;
            fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
                builder.assert_var_eq(bit, Self::N::ZERO);
            }
            fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
                builder.witness_var()
            }
            fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F> {
                builder.witness_felt()
            }
            fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF> {
                builder.witness_ext()
            }
            fn ext2felt(
                builder: &mut Builder<Self>,
                ext: Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
            ) -> [Felt<<Self as FieldGenericConfig>::F>; 4] {
                let felts = core::array::from_fn(|_| builder.uninit());
                builder.push_op(DslIr::CircuitExt2Felt(felts, ext));
                felts
            }
            fn exp_reverse_bits(
                builder: &mut Builder<Self>,
                input: Felt<<Self as FieldGenericConfig>::F>,
                power_bits: Vec<Var<<Self as FieldGenericConfig>::N>>,
            ) -> Felt<<Self as FieldGenericConfig>::F> {
                let mut result = builder.constant(Self::F::ONE);
                let power_f = input;
                let bit_len = power_bits.len();
                for i in 1..=bit_len {
                    let index = bit_len - i;
                    let bit = power_bits[index];
                    let prod = builder.eval(result * power_f);
                    result = builder.select_f(bit, prod, result);
                    builder.assign(power_f, power_f * power_f);
                }
                result
            }
            fn num2bits(
                builder: &mut Builder<Self>,
                num: Felt<<Self as FieldGenericConfig>::F>,
                num_bits: usize,
            ) -> Vec<Var<<Self as FieldGenericConfig>::N>> {
                builder.num2bits_f_circuit(num)[..num_bits].to_vec()
            }
            fn bits2num(
                builder: &mut Builder<Self>,
                bits: impl IntoIterator<Item = Var<<Self as FieldGenericConfig>::N>>,
            ) -> Felt<<Self as FieldGenericConfig>::F> {
                let result = builder.eval(Self::F::ZERO);
                for (i, bit) in bits.into_iter().enumerate() {
                    let to_add: Felt<_> = builder.uninit();
                    let pow2 = builder.constant(Self::F::from_canonical_u32(1 << i));
                    let zero = builder.constant(Self::F::ZERO);
                    builder.push_op(DslIr::CircuitSelectF(bit, pow2, zero, to_add));
                    builder.assign(result, result + to_add);
                }
                result
            }
            fn select_chain_f(
                builder: &mut Builder<Self>,
                should_swap: Self::Bit,
                first: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>> + Clone,
                second: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>> + Clone,
            ) -> Vec<Felt<<Self as FieldGenericConfig>::F>> {
                let id_branch = first.clone().into_iter().chain(second.clone());
                let swap_branch = second.into_iter().chain(first);
                zip(id_branch, swap_branch)
                    .map(|(id_v, sw_v): (Felt<_>, Felt<_>)| -> Felt<_> {
                        let result: Felt<_> = builder.uninit();
                        builder.push_op(DslIr::CircuitSelectF(should_swap, sw_v, id_v, result));
                        result
                    })
                    .collect()
            }
            fn select_chain_ef(
                builder: &mut Builder<Self>,
                should_swap: Self::Bit,
                first: impl IntoIterator<
                        Item = Ext<
                            <Self as FieldGenericConfig>::F,
                            <Self as FieldGenericConfig>::EF,
                        >,
                    > + Clone,
                second: impl IntoIterator<
                        Item = Ext<
                            <Self as FieldGenericConfig>::F,
                            <Self as FieldGenericConfig>::EF,
                        >,
                    > + Clone,
            ) -> Vec<Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>> {
                let id_branch = first.clone().into_iter().chain(second.clone());
                let swap_branch = second.into_iter().chain(first);
                zip(id_branch, swap_branch)
                    .map(|(id_v, sw_v): (Ext<_, _>, Ext<_, _>)| -> Ext<_, _> {
                        let result: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::CircuitSelectE(should_swap, sw_v, id_v, result));
                        result
                    })
                    .collect()
            }
            fn exp_f_bits_precomputed(
                builder: &mut Builder<Self>,
                power_bits: &[Self::Bit],
                two_adic_powers_of_x: &[Felt<Self::F>],
            ) -> Felt<Self::F> {
                let mut result: Felt<_> = builder.eval(Self::F::ONE);
                let one = builder.constant(Self::F::ONE);
                for (&bit, &power) in power_bits.iter().zip(two_adic_powers_of_x) {
                    let multiplier = builder.select_f(bit, power, one);
                    result = builder.eval(multiplier * result);
                }
                result
            }

            fn batch_fri(
                builder: &mut Builder<Self>,
                alpha_pows: Vec<
                    Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
                >,
                p_at_zs: Vec<
                    Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
                >,
                p_at_xs: Vec<Felt<<Self as FieldGenericConfig>::F>>,
            ) -> Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF> {
                let mut acc: Ext<_, _> = builder.uninit();
                builder.push_op(DslIr::ImmE(acc, <Self as FieldGenericConfig>::EF::ZERO));
                for (alpha_pow, p_at_z, p_at_x) in izip!(alpha_pows, p_at_zs, p_at_xs) {
                    let temp_1: Ext<_, _> = builder.uninit();
                    builder.push_op(DslIr::SubEF(temp_1, p_at_z, p_at_x));
                    let temp_2: Ext<_, _> = builder.uninit();
                    builder.push_op(DslIr::MulE(temp_2, alpha_pow, temp_1));
                    let temp_3: Ext<_, _> = builder.uninit();
                    builder.push_op(DslIr::AddE(temp_3, acc, temp_2));
                    acc = temp_3;
                }
                acc
            }
        }
    };
}

impl_embed_circuit_config!(embed_config);
impl_embed_circuit_config!(embed_kb_config);
