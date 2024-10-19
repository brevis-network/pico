use crate::{
    compiler::recursion::{
        prelude::*,
        program_builder::{keys::BaseVerifyingKeyVariable, p3::fri::types::DigestVariable},
    },
    configs::config::RecursionGenericConfig,
    primitives::consts::DIGEST_SIZE,
    recursion::runtime::{HASH_RATE, PERMUTATION_WIDTH},
};
use p3_field::AbstractField;

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<RC: RecursionGenericConfig, V> {
    fn observe(&mut self, builder: &mut Builder<RC>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<RC>, values: Array<RC, V>);
}

pub trait CanSampleVariable<RC: RecursionGenericConfig, V> {
    fn sample(&mut self, builder: &mut Builder<RC>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FeltChallenger<RC: RecursionGenericConfig>:
    CanObserveVariable<RC, Felt<RC::F>> + CanSampleVariable<RC, Felt<RC::F>> + CanSampleBitsVariable<RC>
{
    fn sample_ext(&mut self, builder: &mut Builder<RC>) -> Ext<RC::F, RC::EF>;
}

pub trait CanSampleBitsVariable<RC: RecursionGenericConfig> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<RC>,
        nb_bits: Usize<RC::N>,
    ) -> Array<RC, Var<RC::N>>;
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, DslVariable)]
pub struct DuplexChallengerVariable<RC: RecursionGenericConfig> {
    pub sponge_state: Array<RC, Felt<RC::F>>,
    pub nb_inputs: Var<RC::N>,
    pub input_buffer: Array<RC, Felt<RC::F>>,
    pub nb_outputs: Var<RC::N>,
    pub output_buffer: Array<RC, Felt<RC::F>>,
}

impl<RC: RecursionGenericConfig> DuplexChallengerVariable<RC> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<RC>) -> Self {
        let mut result = DuplexChallengerVariable::<RC> {
            sponge_state: builder.dyn_array(PERMUTATION_WIDTH),
            nb_inputs: builder.eval(RC::N::zero()),
            input_buffer: builder.dyn_array(PERMUTATION_WIDTH),
            nb_outputs: builder.eval(RC::N::zero()),
            output_buffer: builder.dyn_array(PERMUTATION_WIDTH),
        };

        // Constrain the state of the challenger to contain all zeroes.
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut result.sponge_state, i, RC::F::zero());
            builder.set(&mut result.input_buffer, i, RC::F::zero());
            builder.set(&mut result.output_buffer, i, RC::F::zero());
        });
        result
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<RC>) -> Self {
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
        DuplexChallengerVariable::<RC> {
            sponge_state,
            nb_inputs,
            input_buffer,
            nb_outputs,
            output_buffer,
        }
    }

    /// Asserts that the state of this challenger is equal to the state of another challenger.
    pub fn assert_eq(&self, builder: &mut Builder<RC>, other: &Self) {
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

    pub fn reset(&mut self, builder: &mut Builder<RC>) {
        let zero: Var<_> = builder.eval(RC::N::zero());
        let zero_felt: Felt<_> = builder.eval(RC::F::zero());
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

    pub fn duplexing(&mut self, builder: &mut Builder<RC>) {
        builder.range(0, self.nb_inputs).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut self.sponge_state, i, element);
        });
        builder.assign(self.nb_inputs, RC::N::zero());

        builder.poseidon2_permute_mut(&self.sponge_state);

        builder.assign(self.nb_outputs, RC::N::zero());

        for i in 0..PERMUTATION_WIDTH {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut self.output_buffer, i, element);
            builder.assign(self.nb_outputs, self.nb_outputs + RC::N::one());
        }
    }

    fn observe(&mut self, builder: &mut Builder<RC>, value: Felt<RC::F>) {
        builder.assign(self.nb_outputs, RC::N::zero());

        builder.set(&mut self.input_buffer, self.nb_inputs, value);
        builder.assign(self.nb_inputs, self.nb_inputs + RC::N::one());

        builder
            .if_eq(self.nb_inputs, RC::N::from_canonical_usize(HASH_RATE))
            .then(|builder| {
                self.duplexing(builder);
            })
    }

    fn observe_commitment(&mut self, builder: &mut Builder<RC>, commitment: DigestVariable<RC>) {
        for i in 0..DIGEST_SIZE {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        }
    }

    fn sample(&mut self, builder: &mut Builder<RC>) -> Felt<RC::F> {
        let zero: Var<_> = builder.eval(RC::N::zero());
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
        let idx: Var<_> = builder.eval(self.nb_outputs - RC::N::one());
        let output = builder.get(&self.output_buffer, idx);
        builder.assign(self.nb_outputs, self.nb_outputs - RC::N::one());
        output
    }

    fn sample_ext(&mut self, builder: &mut Builder<RC>) -> Ext<RC::F, RC::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn sample_bits(
        &mut self,
        builder: &mut Builder<RC>,
        nb_bits: Usize<RC::N>,
    ) -> Array<RC, Var<RC::N>> {
        let rand_f = self.sample(builder);
        let mut bits = builder.num2bits_f(rand_f);

        builder.range(nb_bits, bits.len()).for_each(|i, builder| {
            builder.set(&mut bits, i, RC::N::zero());
        });

        bits
    }

    pub fn check_witness(
        &mut self,
        builder: &mut Builder<RC>,
        nb_bits: Var<RC::N>,
        witness: Felt<RC::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits.into());
        builder.range(0, nb_bits).for_each(|i, builder| {
            let element = builder.get(&element_bits, i);
            builder.assert_var_eq(element, RC::N::zero());
        });
    }
}

impl<RC: RecursionGenericConfig> CanObserveVariable<RC, Felt<RC::F>>
    for DuplexChallengerVariable<RC>
{
    fn observe(&mut self, builder: &mut Builder<RC>, value: Felt<RC::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(&mut self, builder: &mut Builder<RC>, values: Array<RC, Felt<RC::F>>) {
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

impl<RC: RecursionGenericConfig> CanSampleVariable<RC, Felt<RC::F>>
    for DuplexChallengerVariable<RC>
{
    fn sample(&mut self, builder: &mut Builder<RC>) -> Felt<RC::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<RC: RecursionGenericConfig> CanSampleBitsVariable<RC> for DuplexChallengerVariable<RC> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<RC>,
        nb_bits: Usize<RC::N>,
    ) -> Array<RC, Var<RC::N>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<RC: RecursionGenericConfig> CanObserveVariable<RC, DigestVariable<RC>>
    for DuplexChallengerVariable<RC>
{
    fn observe(&mut self, builder: &mut Builder<RC>, commitment: DigestVariable<RC>) {
        DuplexChallengerVariable::observe_commitment(self, builder, commitment);
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<RC>,
        _values: Array<RC, DigestVariable<RC>>,
    ) {
        todo!()
    }
}

impl<RC: RecursionGenericConfig> CanObserveVariable<RC, BaseVerifyingKeyVariable<RC>>
    for DuplexChallengerVariable<RC>
{
    fn observe(&mut self, builder: &mut Builder<RC>, value: BaseVerifyingKeyVariable<RC>) {
        self.observe_commitment(builder, value.commitment);
        self.observe(builder, value.pc_start)
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<RC>,
        _values: Array<RC, BaseVerifyingKeyVariable<RC>>,
    ) {
        todo!()
    }
}

impl<RC: RecursionGenericConfig> FeltChallenger<RC> for DuplexChallengerVariable<RC> {
    fn sample_ext(&mut self, builder: &mut Builder<RC>) -> Ext<RC::F, RC::EF> {
        DuplexChallengerVariable::sample_ext(self, builder)
    }
}
