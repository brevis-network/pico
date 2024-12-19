use crate::compiler::recursion_v2::{
    circuit::config::CircuitConfig,
    ir::{Builder, DslIr, Ext, Felt, Var},
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_challenger::{CanObserve, CanSample, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{
    extension::BinomialExtensionField, ExtensionField, Field, FieldAlgebra, PrimeField,
    TwoAdicField,
};
use serde::Serialize;
use std::{iter::zip, marker::PhantomData};
// Resembling Plonky3: https://github.com/Plonky3/Plonky3/blob/main/uni-stark/src/config.rs

pub type PackedVal<SC> = <Val<SC> as Field>::Packing;

pub type PackedChallenge<SC> = <Challenge<SC> as ExtensionField<Val<SC>>>::ExtensionPacking;

pub type Com<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Commitment;

// todo: this is confusing and should be considered for refactor
pub type Dom<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Domain;

pub type PcsProverData<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::ProverData;

pub type PcsProof<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Proof;

pub type PcsError<SC> =
    <<SC as StarkGenericConfig>::Pcs as Pcs<Challenge<SC>, Challenger<SC>>>::Error;

// shorthand for types used in the StarkGenericConfig
pub type Val<SC> = <SC as StarkGenericConfig>::Val;

pub type Challenge<SC> = <SC as StarkGenericConfig>::Challenge;

pub type Challenger<SC> = <SC as StarkGenericConfig>::Challenger;

/// A generic config for machines
pub trait StarkGenericConfig: Clone + Serialize + Sync {
    type Val: Field;

    type Domain: PolynomialSpace<Val = Self::Val> + Copy + Sync;

    /// The field from which most random challenges are drawn.
    type Challenge: ExtensionField<Self::Val>;

    /// The challenger (Fiat-Shamir) implementation used.
    type Challenger: FieldChallenger<Self::Val>
        + CanObserve<<Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment>
        + CanSample<Self::Challenge>
        + Clone;

    /// The PCS used to commit to trace polynomials.
    type Pcs: Pcs<Self::Challenge, Self::Challenger, Domain = Self::Domain>
        + Sync
        + ZeroCommitment<Self>;

    /// Get the PCS used by this configuration.
    fn pcs(&self) -> &Self::Pcs;

    /// Initialize a new challenger.
    fn challenger(&self) -> Self::Challenger;

    /// Name of config
    fn name(&self) -> String;
}

pub trait FieldGenericConfig: Clone + Default {
    type N: PrimeField;
    type F: PrimeField + TwoAdicField;
    type EF: ExtensionField<Self::F> + TwoAdicField;
}

#[derive(Debug, Clone, Default)]
pub struct FieldSimpleConfig<F, EF>(PhantomData<(F, EF)>);

impl<F: PrimeField + TwoAdicField, EF: ExtensionField<F> + TwoAdicField> FieldGenericConfig
    for FieldSimpleConfig<F, EF>
{
    type N = F;
    type F = F;
    type EF = EF;
}

pub trait ZeroCommitment<SC: StarkGenericConfig> {
    fn zero_commitment(&self) -> Com<SC>;
}

pub struct SimpleFriConfig {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub proof_of_work_bits: usize,
}

#[derive(Clone, Default, Debug)]
pub struct OuterConfig;
impl FieldGenericConfig for OuterConfig {
    type N = Bn254Fr;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}

impl CircuitConfig for OuterConfig {
    type Bit = Var<<Self as FieldGenericConfig>::N>;
    fn assert_bit_zero(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_var_eq(bit, Self::N::ZERO);
    }
    fn assert_bit_one(builder: &mut Builder<Self>, bit: Self::Bit) {
        builder.assert_var_eq(bit, Self::N::ONE);
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
                Item = Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
            > + Clone,
        second: impl IntoIterator<
                Item = Ext<<Self as FieldGenericConfig>::F, <Self as FieldGenericConfig>::EF>,
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
}
