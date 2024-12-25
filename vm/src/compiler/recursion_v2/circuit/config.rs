//TODO: reorg config

use super::{
    builder::CircuitV2Builder,
    challenger::{
        CanCopyChallenger, CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
        MultiField32ChallengerVariable, SpongeChallengerShape,
    },
    hash::{FieldHasherVariable, Posedion2BabyBearHasherVariable},
    utils::{felt_bytes_to_bn254_var, felts_to_bn254_var, words_to_bytes},
};
use crate::configs::config::SimpleFriConfig;
use crate::{
    compiler::recursion_v2::ir::{Builder, Ext, Felt, Var, Variable},
    configs::{
        config::{FieldGenericConfig, StarkGenericConfig},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_ValMmcs}, // TODO: use instance config
    },
    instances::configs::{
        embed_config::{SC_ValMmcs as EmbedValMmcs, StarkConfig as EmbedSC},
        recur_config::FieldConfig,
    },
    primitives::consts::EXTENSION_DEGREE,
    recursion_v2::air::RecursionPublicValues,
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, Mmcs};
use p3_dft::Radix2DitParallel;
use p3_field::FieldAlgebra;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use std::{
    iter::{repeat, zip},
    ops::{Add, Mul},
};

type EF = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge;

pub type PcsConfig<CC> = FriConfig<
    ExtensionMmcs<
        <CC as StarkGenericConfig>::Val,
        <CC as StarkGenericConfig>::Challenge,
        <CC as BabyBearFriConfig>::ValMmcs,
    >,
>;

pub type Digest<CC, SC> = <SC as FieldHasherVariable<CC>>::DigestVariable;

pub type FriMmcs<CC> = ExtensionMmcs<BabyBear, EF, <CC as BabyBearFriConfig>::ValMmcs>;

pub trait BabyBearFriConfig: // Note: use BabyBearPoseidon2
    StarkGenericConfig<
        Val = BabyBear,
        Challenge = EF,
        Challenger = Self::FriChallenger,
        Pcs = TwoAdicFriPcs<
            BabyBear,
            Radix2DitParallel<BabyBear>,
            Self::ValMmcs,
            ExtensionMmcs<BabyBear, EF, Self::ValMmcs>,
        >,
    >
{
    type ValMmcs: Mmcs<BabyBear, ProverData<RowMajorMatrix<BabyBear>> = Self::RowMajorProverData>
    + Send
    + Sync;
    type RowMajorProverData: Clone + Send + Sync;
    type FriChallenger: CanObserve<<Self::ValMmcs as Mmcs<BabyBear>>::Commitment>
    + CanSample<EF>
    + GrindingChallenger<Witness = BabyBear>
    + FieldChallenger<BabyBear>;

    fn fri_config(&self) ->&SimpleFriConfig;

    fn challenger_shape(challenger: &Self::FriChallenger) -> SpongeChallengerShape;
}

pub trait BabyBearFriConfigVariable<CC: CircuitConfig<F = BabyBear>>:
    BabyBearFriConfig + FieldHasherVariable<CC> + Posedion2BabyBearHasherVariable<CC>
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

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit);

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

impl CircuitConfig for FieldConfig {
    type Bit = Felt<<Self as FieldGenericConfig>::F>;

    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, Self::F::ZERO);
    }

    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_felt_eq(bit, Self::F::ONE);
    }

    fn read_bit(builder: &mut Builder<Self>) -> Self::Bit {
        builder.hint_felt_v2()
    }

    fn read_felt(builder: &mut Builder<Self>) -> Felt<Self::F> {
        builder.hint_felt_v2()
    }

    fn read_ext(builder: &mut Builder<Self>) -> Ext<Self::F, Self::EF> {
        builder.hint_ext_v2()
    }

    fn ext2felt(
        builder: &mut Builder<Self>,
        ext: Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
    ) -> [Felt<<Self as FieldGenericConfig>::F>; EXTENSION_DEGREE] {
        builder.ext2felt_v2(ext)
    }

    fn num2bits(
        builder: &mut Builder<Self>,
        num: Felt<<Self as FieldGenericConfig>::F>,
        num_bits: usize,
    ) -> Vec<Felt<<Self as FieldGenericConfig>::F>> {
        builder.num2bits_v2_f(num, num_bits)
    }

    fn bits2num(
        builder: &mut Builder<Self>,
        bits: impl IntoIterator<Item = Felt<<Self as FieldGenericConfig>::F>>,
    ) -> Felt<<Self as FieldGenericConfig>::F> {
        builder.bits2num_v2_f(bits)
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
                Item = Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
            > + Clone,
        second: impl IntoIterator<
                Item = Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
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
        builder.exp_reverse_bits_v2(input, power_bits)
    }
}

impl BabyBearFriConfig for BabyBearPoseidon2 {
    type ValMmcs = SC_ValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;
    type RowMajorProverData = <SC_ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>;

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

impl<CC: CircuitConfig<F = BabyBear, Bit = Felt<BabyBear>>> BabyBearFriConfigVariable<CC>
    for BabyBearPoseidon2
{
    type FriChallengerVariable = DuplexChallengerVariable<CC>;

    fn challenger_variable(&self, builder: &mut Builder<CC>) -> Self::FriChallengerVariable {
        DuplexChallengerVariable::new(builder)
    }

    fn commit_recursion_public_values(
        builder: &mut Builder<CC>,
        public_values: RecursionPublicValues<Felt<<CC>::F>>,
    ) {
        builder.commit_public_values_v2(public_values);
    }
}

impl BabyBearFriConfig for EmbedSC {
    type ValMmcs = EmbedValMmcs;
    type FriChallenger = <Self as StarkGenericConfig>::Challenger;

    type RowMajorProverData =
        <EmbedValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>;

    fn fri_config(&self) -> &SimpleFriConfig {
        self.fri_config()
    }

    fn challenger_shape(_challenger: &Self::FriChallenger) -> SpongeChallengerShape {
        unimplemented!("Shape not supported for outer fri challenger");
    }
}

impl<C: CircuitConfig<F = BabyBear, N = Bn254Fr, Bit = Var<Bn254Fr>>> BabyBearFriConfigVariable<C>
    for EmbedSC
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

pub fn select_chain<'a, FC, R, S>(
    builder: &'a mut Builder<FC>,
    should_swap: R,
    first: impl IntoIterator<Item = S> + Clone + 'a,
    second: impl IntoIterator<Item = S> + Clone + 'a,
) -> impl Iterator<Item = S> + 'a
where
    FC: FieldGenericConfig,
    R: Variable<FC> + 'a,
    S: Variable<FC> + 'a,
    <R as Variable<FC>>::Expression: FieldAlgebra
        + Mul<<S as Variable<FC>>::Expression, Output = <S as Variable<FC>>::Expression>,
    <S as Variable<FC>>::Expression: Add<Output = <S as Variable<FC>>::Expression>,
{
    let should_swap: <R as Variable<FC>>::Expression = should_swap.into();
    let one = <R as Variable<FC>>::Expression::ONE;
    let should_not_swap = one - should_swap.clone();

    let id_branch = first
        .clone()
        .into_iter()
        .chain(second.clone())
        .map(<S as Variable<FC>>::Expression::from);
    let swap_branch = second
        .into_iter()
        .chain(first)
        .map(<S as Variable<FC>>::Expression::from);
    zip(
        zip(id_branch, swap_branch),
        zip(repeat(should_not_swap), repeat(should_swap)),
    )
    .map(|((id_v, sw_v), (id_c, sw_c))| builder.eval(id_c * id_v + sw_c * sw_v))
}
