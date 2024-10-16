use crate::{
    compiler::recursion::{
        prelude::{
            Array, Builder, Config, DslVariable, Ext, Felt, MemIndex, MemVariable, Ptr, Usize, Var,
            Variable,
        },
        program_builder::{keys::BaseVerifyingKeyVariable, p3::fri::types::DigestVariable},
    },
    primitives::consts::DIGEST_SIZE,
    recursion::runtime::{HASH_RATE, PERMUTATION_WIDTH},
};
use p3_field::AbstractField;

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<CF: Config, V> {
    fn observe(&mut self, builder: &mut Builder<CF>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<CF>, values: Array<CF, V>);
}

pub trait CanSampleVariable<CF: Config, V> {
    fn sample(&mut self, builder: &mut Builder<CF>) -> V;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FeltChallenger<CF: Config>:
    CanObserveVariable<CF, Felt<CF::F>> + CanSampleVariable<CF, Felt<CF::F>> + CanSampleBitsVariable<CF>
{
    fn sample_ext(&mut self, builder: &mut Builder<CF>) -> Ext<CF::F, CF::EF>;
}

pub trait CanSampleBitsVariable<CF: Config> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<CF>,
        nb_bits: Usize<CF::N>,
    ) -> Array<CF, Var<CF::N>>;
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, DslVariable)]
pub struct DuplexChallengerVariable<CF: Config> {
    pub sponge_state: Array<CF, Felt<CF::F>>,
    pub nb_inputs: Var<CF::N>,
    pub input_buffer: Array<CF, Felt<CF::F>>,
    pub nb_outputs: Var<CF::N>,
    pub output_buffer: Array<CF, Felt<CF::F>>,
}

impl<CF: Config> DuplexChallengerVariable<CF> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<CF>) -> Self {
        let mut result = DuplexChallengerVariable::<CF> {
            sponge_state: builder.dyn_array(PERMUTATION_WIDTH),
            nb_inputs: builder.eval(CF::N::zero()),
            input_buffer: builder.dyn_array(PERMUTATION_WIDTH),
            nb_outputs: builder.eval(CF::N::zero()),
            output_buffer: builder.dyn_array(PERMUTATION_WIDTH),
        };

        // Constrain the state of the challenger to contain all zeroes.
        builder.range(0, PERMUTATION_WIDTH).for_each(|i, builder| {
            builder.set(&mut result.sponge_state, i, CF::F::zero());
            builder.set(&mut result.input_buffer, i, CF::F::zero());
            builder.set(&mut result.output_buffer, i, CF::F::zero());
        });
        result
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<CF>) -> Self {
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
        DuplexChallengerVariable::<CF> {
            sponge_state,
            nb_inputs,
            input_buffer,
            nb_outputs,
            output_buffer,
        }
    }

    /// Asserts that the state of this challenger is equal to the state of another challenger.
    pub fn assert_eq(&self, builder: &mut Builder<CF>, other: &Self) {
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

    pub fn reset(&mut self, builder: &mut Builder<CF>) {
        let zero: Var<_> = builder.eval(CF::N::zero());
        let zero_felt: Felt<_> = builder.eval(CF::F::zero());
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

    pub fn duplexing(&mut self, builder: &mut Builder<CF>) {
        builder.range(0, self.nb_inputs).for_each(|i, builder| {
            let element = builder.get(&self.input_buffer, i);
            builder.set(&mut self.sponge_state, i, element);
        });
        builder.assign(self.nb_inputs, CF::N::zero());

        builder.poseidon2_permute_mut(&self.sponge_state);

        builder.assign(self.nb_outputs, CF::N::zero());

        for i in 0..PERMUTATION_WIDTH {
            let element = builder.get(&self.sponge_state, i);
            builder.set(&mut self.output_buffer, i, element);
            builder.assign(self.nb_outputs, self.nb_outputs + CF::N::one());
        }
    }

    fn observe(&mut self, builder: &mut Builder<CF>, value: Felt<CF::F>) {
        builder.assign(self.nb_outputs, CF::N::zero());

        builder.set(&mut self.input_buffer, self.nb_inputs, value);
        builder.assign(self.nb_inputs, self.nb_inputs + CF::N::one());

        builder
            .if_eq(self.nb_inputs, CF::N::from_canonical_usize(HASH_RATE))
            .then(|builder| {
                self.duplexing(builder);
            })
    }

    fn observe_commitment(&mut self, builder: &mut Builder<CF>, commitment: DigestVariable<CF>) {
        for i in 0..DIGEST_SIZE {
            let element = builder.get(&commitment, i);
            self.observe(builder, element);
        }
    }

    fn sample(&mut self, builder: &mut Builder<CF>) -> Felt<CF::F> {
        let zero: Var<_> = builder.eval(CF::N::zero());
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
        let idx: Var<_> = builder.eval(self.nb_outputs - CF::N::one());
        let output = builder.get(&self.output_buffer, idx);
        builder.assign(self.nb_outputs, self.nb_outputs - CF::N::one());
        output
    }

    fn sample_ext(&mut self, builder: &mut Builder<CF>) -> Ext<CF::F, CF::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn sample_bits(
        &mut self,
        builder: &mut Builder<CF>,
        nb_bits: Usize<CF::N>,
    ) -> Array<CF, Var<CF::N>> {
        let rand_f = self.sample(builder);
        let mut bits = builder.num2bits_f(rand_f);

        builder.range(nb_bits, bits.len()).for_each(|i, builder| {
            builder.set(&mut bits, i, CF::N::zero());
        });

        bits
    }

    pub fn check_witness(
        &mut self,
        builder: &mut Builder<CF>,
        nb_bits: Var<CF::N>,
        witness: Felt<CF::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits.into());
        builder.range(0, nb_bits).for_each(|i, builder| {
            let element = builder.get(&element_bits, i);
            builder.assert_var_eq(element, CF::N::zero());
        });
    }
}

impl<CF: Config> CanObserveVariable<CF, Felt<CF::F>> for DuplexChallengerVariable<CF> {
    fn observe(&mut self, builder: &mut Builder<CF>, value: Felt<CF::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(&mut self, builder: &mut Builder<CF>, values: Array<CF, Felt<CF::F>>) {
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

impl<CF: Config> CanSampleVariable<CF, Felt<CF::F>> for DuplexChallengerVariable<CF> {
    fn sample(&mut self, builder: &mut Builder<CF>) -> Felt<CF::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<CF: Config> CanSampleBitsVariable<CF> for DuplexChallengerVariable<CF> {
    fn sample_bits(
        &mut self,
        builder: &mut Builder<CF>,
        nb_bits: Usize<CF::N>,
    ) -> Array<CF, Var<CF::N>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<CF: Config> CanObserveVariable<CF, DigestVariable<CF>> for DuplexChallengerVariable<CF> {
    fn observe(&mut self, builder: &mut Builder<CF>, commitment: DigestVariable<CF>) {
        DuplexChallengerVariable::observe_commitment(self, builder, commitment);
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<CF>,
        _values: Array<CF, DigestVariable<CF>>,
    ) {
        todo!()
    }
}

impl<CF: Config> CanObserveVariable<CF, BaseVerifyingKeyVariable<CF>>
    for DuplexChallengerVariable<CF>
{
    fn observe(&mut self, builder: &mut Builder<CF>, value: BaseVerifyingKeyVariable<CF>) {
        self.observe_commitment(builder, value.commitment);
        self.observe(builder, value.pc_start)
    }

    fn observe_slice(
        &mut self,
        _builder: &mut Builder<CF>,
        _values: Array<CF, BaseVerifyingKeyVariable<CF>>,
    ) {
        todo!()
    }
}

impl<CF: Config> FeltChallenger<CF> for DuplexChallengerVariable<CF> {
    fn sample_ext(&mut self, builder: &mut Builder<CF>) -> Ext<CF::F, CF::EF> {
        DuplexChallengerVariable::sample_ext(self, builder)
    }
}
