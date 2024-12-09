use crate::{
    compiler::recursion::{
        prelude::*,
        program_builder::{keys::BaseVerifyingKeyVariable, p3::fri::types::DigestVariable},
    },
    configs::config::FieldGenericConfig,
    primitives::consts::{DIGEST_SIZE, PERMUTATION_RATE, PERMUTATION_WIDTH},
    recursion::runtime::HASH_RATE,
};
use p3_field::FieldAlgebra;

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<FC: FieldGenericConfig, V> {
    fn observe(&mut self, builder: &mut Builder<FC>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<FC>, values: Array<FC, V>);
}

pub trait CanSampleVariable<FC: FieldGenericConfig, V> {
    fn sample(&mut self, builder: &mut Builder<FC>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FeltChallenger<FC: FieldGenericConfig>:
    CanObserveVariable<FC, Felt<FC::F>> + CanSampleVariable<FC, Felt<FC::F>> + CanSampleBitsVariable<FC>
{
    fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF>;
}

pub trait CanSampleBitsVariable<FC: FieldGenericConfig> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<FC>,
        nb_bits: Usize<FC::N>,
    ) -> Array<FC, Var<FC::N>>;
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, DslVariable)]
pub struct DuplexChallengerVariable<FC: FieldGenericConfig> {
    pub sponge_state: Array<FC, Felt<FC::F>>,
    pub nb_inputs: Var<FC::N>,
    pub input_buffer: Array<FC, Felt<FC::F>>,
    pub nb_outputs: Var<FC::N>,
    pub output_buffer: Array<FC, Felt<FC::F>>,
}

impl<FC: FieldGenericConfig> DuplexChallengerVariable<FC> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<FC>) -> Self {
        let mut result = DuplexChallengerVariable::<FC> {
            sponge_state: builder.dyn_array(PERMUTATION_WIDTH),
            nb_inputs: builder.eval(FC::N::ZERO),
            input_buffer: builder.dyn_array(PERMUTATION_WIDTH),
            nb_outputs: builder.eval(FC::N::ZERO),
            output_buffer: builder.dyn_array(PERMUTATION_WIDTH),
        };

        // Constrain the state of the challenger to contain all zeroes.
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut result.sponge_state, i, FC::F::ZERO);
            builder.set(&mut result.input_buffer, i, FC::F::ZERO);
            builder.set(&mut result.output_buffer, i, FC::F::ZERO);
        });
        result
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<FC>) -> Self {
        let mut sponge_state = builder.dyn_array(PERMUTATION_WIDTH);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut sponge_state, i, element);
        });
        let nb_inputs = builder.eval(self.nb_inputs);
        let mut input_buffer = builder.dyn_array(PERMUTATION_WIDTH);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut input_buffer, i, element);
        });
        let nb_outputs = builder.eval(self.nb_outputs);
        let mut output_buffer = builder.dyn_array(PERMUTATION_WIDTH);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.output_buffer, i);
            builder.set(&mut output_buffer, i, element);
        });
        DuplexChallengerVariable::<FC> {
            sponge_state,
            nb_inputs,
            input_buffer,
            nb_outputs,
            output_buffer,
        }
    }

    /// Asserts that the state of this challenger is equal to the state of another challenger.
    pub fn assert_eq(&self, builder: &mut Builder<FC>, other: &Self) {
        builder.assert_var_eq(self.nb_inputs, other.nb_inputs);
        builder.assert_var_eq(self.nb_outputs, other.nb_outputs);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            let element = builder.get(&self.sponge_state, i);
            let other_element = builder.get(&other.sponge_state, i);
            builder.assert_felt_eq(element, other_element);
        });
        builder.range(0, self.nb_inputs).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            let other_element = builder.get(&other.input_buffer, i);
            builder.assert_felt_eq(element, other_element);
        });
        builder.range(0, self.nb_outputs).for_each(|i, builder| {
            let element = builder.get(&self.output_buffer, i);
            let other_element = builder.get(&other.output_buffer, i);
            builder.assert_felt_eq(element, other_element);
        });
    }

    pub fn reset(&mut self, builder: &mut Builder<FC>) {
        let zero: Var<_> = builder.eval(FC::N::ZERO);
        let zero_felt: Felt<_> = builder.eval(FC::F::ZERO);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut self.sponge_state, i, zero_felt);
        });
        builder.assign(self.nb_inputs, zero);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut self.input_buffer, i, zero_felt);
        });
        builder.assign(self.nb_outputs, zero);
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut self.output_buffer, i, zero_felt);
        });
    }

    pub fn duplexing(&mut self, builder: &mut Builder<FC>) {
        builder.range(0, self.nb_inputs).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut self.sponge_state, i, element);
        });
        builder.assign(self.nb_inputs, FC::N::ZERO);

        builder.poseidon2_permute_mut(&self.sponge_state);

        builder.assign(self.nb_outputs, FC::N::ZERO);

        // todo: update for permutation
        for i in 0..PERMUTATION_RATE {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut self.output_buffer, i, element);
            builder.assign(self.nb_outputs, self.nb_outputs + FC::N::ONE);
        }
    }

    fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<FC::F>) {
        builder.assign(self.nb_outputs, FC::N::ZERO);

        builder.set(&mut self.input_buffer, self.nb_inputs, value);
        builder.assign(self.nb_inputs, self.nb_inputs + FC::N::ONE);

        builder
            .if_eq(self.nb_inputs, FC::N::from_canonical_usize(HASH_RATE))
            .then(|builder| {
                self.duplexing(builder);
            })
    }

    fn observe_commitment(&mut self, builder: &mut Builder<FC>, commitment: DigestVariable<FC>) {
        for i in 0..DIGEST_SIZE {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        }
    }

    fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<FC::F> {
        let zero: Var<_> = builder.eval(FC::N::ZERO);
        builder.if_ne(self.nb_inputs, zero).then_or_else(
            |builder| {
                self.clone().duplexing(builder);
            },
            |builder| {
                builder.if_eq(self.nb_outputs, zero).then(|builder| {
                    self.clone().duplexing(builder);
                });
            },
        );
        let idx: Var<_> = builder.eval(self.nb_outputs - FC::N::ONE);
        let output = builder.get(&self.output_buffer, idx);
        builder.assign(self.nb_outputs, self.nb_outputs - FC::N::ONE);
        output
    }

    fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn sample_bits(
        &mut self,
        builder: &mut Builder<FC>,
        nb_bits: Usize<FC::N>,
    ) -> Array<FC, Var<FC::N>> {
        let rand_f = self.sample(builder);
        let mut bits = builder.num2bits_f(rand_f);

        builder.range(nb_bits, bits.len()).for_each(|i, builder| {
            builder.set(&mut bits, i, FC::N::ZERO);
        });

        bits
    }

    pub fn check_witness(
        &mut self,
        builder: &mut Builder<FC>,
        nb_bits: Var<FC::N>,
        witness: Felt<FC::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits.into());
        builder.range(0, nb_bits).for_each(|i, builder| {
            let element = builder.get(&element_bits, i);
            builder.assert_var_eq(element, FC::N::ZERO);
        });
    }
}

impl<FC: FieldGenericConfig> CanObserveVariable<FC, Felt<FC::F>> for DuplexChallengerVariable<FC> {
    fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<FC::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(&mut self, builder: &mut Builder<FC>, values: Array<FC, Felt<FC::F>>) {
        match values {
            Array::Dyn(_, len) => {
                builder.range(0, len).for_each(|i, builder| {
                    let element = builder.get(&values, i);
                    self.observe(builder, element);
                });
            }
            Array::Fixed(values) => {
                values.iter().for_each(|value| {
                    self.observe(builder, *value);
                });
            }
        }
    }
}

impl<FC: FieldGenericConfig> CanSampleVariable<FC, Felt<FC::F>> for DuplexChallengerVariable<FC> {
    fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<FC::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<FC: FieldGenericConfig> CanSampleBitsVariable<FC> for DuplexChallengerVariable<FC> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<FC>,
        nb_bits: Usize<FC::N>,
    ) -> Array<FC, Var<FC::N>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<FC: FieldGenericConfig> CanObserveVariable<FC, DigestVariable<FC>>
    for DuplexChallengerVariable<FC>
{
    fn observe(&mut self, builder: &mut Builder<FC>, commitment: DigestVariable<FC>) {
        DuplexChallengerVariable::observe_commitment(self, builder, commitment);
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<FC>,
        _values: Array<FC, DigestVariable<FC>>,
    ) {
        todo!()
    }
}

impl<FC: FieldGenericConfig> CanObserveVariable<FC, BaseVerifyingKeyVariable<FC>>
    for DuplexChallengerVariable<FC>
{
    fn observe(&mut self, builder: &mut Builder<FC>, value: BaseVerifyingKeyVariable<FC>) {
        self.observe_commitment(builder, value.commitment);
        self.observe(builder, value.pc_start)
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<FC>,
        _values: Array<FC, BaseVerifyingKeyVariable<FC>>,
    ) {
        todo!()
    }
}

impl<FC: FieldGenericConfig> FeltChallenger<FC> for DuplexChallengerVariable<FC> {
    fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF> {
        DuplexChallengerVariable::sample_ext(self, builder)
    }
}
