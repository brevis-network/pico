use super::builder::CircuitV2Builder;
use crate::{
    compiler::recursion_v2::ir::{Builder, DslIr, Ext, Felt, Var},
    configs::config::FieldGenericConfig,
    emulator::recursion::public_values::ChallengerPublicValues,
    primitives::consts::{
        MULTI_FIELD_CHALLENGER_DIGEST_SIZE, MULTI_FIELD_CHALLENGER_RATE,
        MULTI_FIELD_CHALLENGER_WIDTH, NUM_BITS, PERMUTATION_RATE, PERMUTATION_WIDTH,
    },
};
use p3_field::{Field, FieldAlgebra};

pub trait CanCopyChallenger<FC: FieldGenericConfig> {
    fn copy(&self, builder: &mut Builder<FC>) -> Self;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpongeChallengerShape {
    pub input_buffer_len: usize,
    pub output_buffer_len: usize,
}

/// Reference: [p3_challenger::CanObserve].
pub trait CanObserveVariable<FC: FieldGenericConfig, V> {
    fn observe(&mut self, builder: &mut Builder<FC>, value: V);

    fn observe_slice(&mut self, builder: &mut Builder<FC>, values: impl IntoIterator<Item = V>) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

pub trait CanSampleVariable<FC: FieldGenericConfig, V> {
    fn sample(&mut self, builder: &mut Builder<FC>) -> V;
}

pub trait CanSampleBitsVariable<FC: FieldGenericConfig, V> {
    fn sample_bits(&mut self, builder: &mut Builder<FC>, nb_bits: usize) -> Vec<V>;
}

/// Reference: [p3_challenger::FieldChallenger].
pub trait FieldChallengerVariable<FC: FieldGenericConfig, Bit>:
    CanObserveVariable<FC, Felt<FC::F>>
    + CanSampleVariable<FC, Felt<FC::F>>
    + CanSampleBitsVariable<FC, Bit>
{
    fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF>;

    fn check_witness(&mut self, builder: &mut Builder<FC>, nb_bits: usize, witness: Felt<FC::F>);

    fn duplexing(&mut self, builder: &mut Builder<FC>);
}

/// Reference: [p3_challenger::DuplexChallenger]
#[derive(Clone, Debug)]
pub struct DuplexChallengerVariable<FC: FieldGenericConfig> {
    pub sponge_state: [Felt<FC::F>; PERMUTATION_WIDTH],
    pub input_buffer: Vec<Felt<FC::F>>,
    pub output_buffer: Vec<Felt<FC::F>>,
}

impl<FC: FieldGenericConfig> DuplexChallengerVariable<FC> {
    /// Creates a new duplex challenger with the default state.
    pub fn new(builder: &mut Builder<FC>) -> Self {
        DuplexChallengerVariable::<FC> {
            sponge_state: core::array::from_fn(|_| builder.eval(FC::F::ZERO)),
            input_buffer: vec![],
            output_buffer: vec![],
        }
    }

    /// Creates a new challenger with the same state as an existing challenger.
    pub fn copy(&self, builder: &mut Builder<FC>) -> Self {
        let DuplexChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
        } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<FC::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        DuplexChallengerVariable::<FC> {
            sponge_state,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }

    fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<FC::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);

        if self.input_buffer.len() == PERMUTATION_RATE {
            self.duplexing(builder);
        }
    }

    fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<FC::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer
            .pop()
            .expect("output buffer should be non-empty")
    }

    fn sample_bits(&mut self, builder: &mut Builder<FC>, nb_bits: usize) -> Vec<Felt<FC::F>> {
        assert!(nb_bits <= NUM_BITS);
        let rand_f = self.sample(builder);
        let mut rand_f_bits = builder.num2bits_v2_f(rand_f, NUM_BITS);
        rand_f_bits.truncate(nb_bits);
        rand_f_bits
    }

    pub fn public_values(&self, builder: &mut Builder<FC>) -> ChallengerPublicValues<Felt<FC::F>> {
        assert!(self.input_buffer.len() <= PERMUTATION_WIDTH);
        assert!(self.output_buffer.len() <= PERMUTATION_WIDTH);

        let sponge_state = self.sponge_state;
        let num_inputs = builder.eval(FC::F::from_canonical_usize(self.input_buffer.len()));
        let num_outputs = builder.eval(FC::F::from_canonical_usize(self.output_buffer.len()));

        let input_buffer: [_; PERMUTATION_WIDTH] = self
            .input_buffer
            .iter()
            .copied()
            .chain((self.input_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(FC::F::ZERO)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let output_buffer: [_; PERMUTATION_WIDTH] = self
            .output_buffer
            .iter()
            .copied()
            .chain((self.output_buffer.len()..PERMUTATION_WIDTH).map(|_| builder.eval(FC::F::ZERO)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        ChallengerPublicValues {
            sponge_state,
            num_inputs,
            input_buffer,
            num_outputs,
            output_buffer,
        }
    }
}

impl<FC: FieldGenericConfig> CanCopyChallenger<FC> for DuplexChallengerVariable<FC> {
    fn copy(&self, builder: &mut Builder<FC>) -> Self {
        DuplexChallengerVariable::copy(self, builder)
    }
}

impl<FC: FieldGenericConfig> CanObserveVariable<FC, Felt<FC::F>> for DuplexChallengerVariable<FC> {
    fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<FC::F>) {
        DuplexChallengerVariable::observe(self, builder, value);
    }

    fn observe_slice(
        &mut self,
        builder: &mut Builder<FC>,
        values: impl IntoIterator<Item = Felt<FC::F>>,
    ) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<FC: FieldGenericConfig, const N: usize> CanObserveVariable<FC, [Felt<FC::F>; N]>
    for DuplexChallengerVariable<FC>
{
    fn observe(&mut self, builder: &mut Builder<FC>, values: [Felt<FC::F>; N]) {
        for value in values {
            self.observe(builder, value);
        }
    }
}

impl<FC: FieldGenericConfig> CanSampleVariable<FC, Felt<FC::F>> for DuplexChallengerVariable<FC> {
    fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<FC::F> {
        DuplexChallengerVariable::sample(self, builder)
    }
}

impl<FC: FieldGenericConfig> CanSampleBitsVariable<FC, Felt<FC::F>>
    for DuplexChallengerVariable<FC>
{
    fn sample_bits(&mut self, builder: &mut Builder<FC>, nb_bits: usize) -> Vec<Felt<FC::F>> {
        DuplexChallengerVariable::sample_bits(self, builder, nb_bits)
    }
}

impl<FC: FieldGenericConfig> FieldChallengerVariable<FC, Felt<FC::F>>
    for DuplexChallengerVariable<FC>
{
    fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.ext_from_base_slice(&[a, b, c, d])
    }

    fn check_witness(
        &mut self,
        builder: &mut Builder<FC>,
        nb_bits: usize,
        witness: Felt<<FC as FieldGenericConfig>::F>,
    ) {
        self.observe(builder, witness);
        let element_bits = self.sample_bits(builder, nb_bits);
        for bit in element_bits {
            builder.assert_felt_eq(bit, FC::F::ZERO);
        }
    }

    fn duplexing(&mut self, builder: &mut Builder<FC>) {
        assert!(self.input_buffer.len() <= PERMUTATION_RATE);

        self.sponge_state[0..self.input_buffer.len()].copy_from_slice(self.input_buffer.as_slice());
        self.input_buffer.clear();

        self.sponge_state = builder.poseidon2_permute_v2(self.sponge_state);

        self.output_buffer.clear();
        self.output_buffer
            .extend_from_slice(&self.sponge_state[0..PERMUTATION_RATE]);
    }
}

#[derive(Clone)]
pub struct MultiField32ChallengerVariable<FC: FieldGenericConfig> {
    sponge_state: [Var<FC::N>; MULTI_FIELD_CHALLENGER_WIDTH],
    input_buffer: Vec<Felt<FC::F>>,
    output_buffer: Vec<Felt<FC::F>>,
    num_f_elms: usize,
}

impl<FC: FieldGenericConfig> MultiField32ChallengerVariable<FC> {
    pub fn new(builder: &mut Builder<FC>) -> Self {
        MultiField32ChallengerVariable::<FC> {
            sponge_state: core::array::from_fn(|_| builder.eval(FC::N::ZERO)),
            input_buffer: vec![],
            output_buffer: vec![],
            num_f_elms: FC::N::bits() / 64,
        }
    }

    pub fn duplexing(&mut self, builder: &mut Builder<FC>) {
        assert!(self.input_buffer.len() <= self.num_f_elms * MULTI_FIELD_CHALLENGER_RATE);

        for (i, f_chunk) in self.input_buffer.chunks(self.num_f_elms).enumerate() {
            self.sponge_state[i] = reduce_32(builder, f_chunk);
        }
        self.input_buffer.clear();

        builder.push_op(DslIr::CircuitPoseidon2Permute(self.sponge_state));

        self.output_buffer.clear();
        for &pf_val in self.sponge_state.iter() {
            let f_vals = split_32(builder, pf_val, self.num_f_elms);
            for f_val in f_vals {
                self.output_buffer.push(f_val);
            }
        }
    }

    pub fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<FC::F>) {
        self.output_buffer.clear();

        self.input_buffer.push(value);
        if self.input_buffer.len() == self.num_f_elms * MULTI_FIELD_CHALLENGER_RATE {
            self.duplexing(builder);
        }
    }

    pub fn observe_commitment(
        &mut self,
        builder: &mut Builder<FC>,
        value: [Var<FC::N>; MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        for val in value {
            let f_vals: Vec<Felt<FC::F>> = split_32(builder, val, self.num_f_elms);
            for f_val in f_vals {
                self.observe(builder, f_val);
            }
        }
    }

    pub fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<FC::F> {
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(builder);
        }

        self.output_buffer
            .pop()
            .expect("output buffer should be non-empty")
    }

    pub fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF> {
        let a = self.sample(builder);
        let b = self.sample(builder);
        let c = self.sample(builder);
        let d = self.sample(builder);
        builder.felts2ext(&[a, b, c, d])
    }

    pub fn sample_bits(&mut self, builder: &mut Builder<FC>, bits: usize) -> Vec<Var<FC::N>> {
        let rand_f = self.sample(builder);
        builder.num2bits_f_circuit(rand_f)[0..bits].to_vec()
    }

    pub fn check_witness(&mut self, builder: &mut Builder<FC>, bits: usize, witness: Felt<FC::F>) {
        self.observe(builder, witness);
        let element = self.sample_bits(builder, bits);
        for bit in element {
            builder.assert_var_eq(bit, FC::N::from_canonical_usize(0));
        }
    }
}

impl<FC: FieldGenericConfig> CanCopyChallenger<FC> for MultiField32ChallengerVariable<FC> {
    /// Creates a new challenger with the same state as an existing challenger.
    fn copy(&self, builder: &mut Builder<FC>) -> Self {
        let MultiField32ChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
            num_f_elms,
        } = self;
        let sponge_state = sponge_state.map(|x| builder.eval(x));
        let mut copy_vec = |v: &Vec<Felt<FC::F>>| v.iter().map(|x| builder.eval(*x)).collect();
        MultiField32ChallengerVariable::<FC> {
            sponge_state,
            num_f_elms: *num_f_elms,
            input_buffer: copy_vec(input_buffer),
            output_buffer: copy_vec(output_buffer),
        }
    }
}

impl<FC: FieldGenericConfig> CanObserveVariable<FC, Felt<FC::F>>
    for MultiField32ChallengerVariable<FC>
{
    fn observe(&mut self, builder: &mut Builder<FC>, value: Felt<FC::F>) {
        MultiField32ChallengerVariable::observe(self, builder, value);
    }
}

impl<FC: FieldGenericConfig>
    CanObserveVariable<FC, [Var<FC::N>; MULTI_FIELD_CHALLENGER_DIGEST_SIZE]>
    for MultiField32ChallengerVariable<FC>
{
    fn observe(
        &mut self,
        builder: &mut Builder<FC>,
        value: [Var<FC::N>; MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    ) {
        self.observe_commitment(builder, value)
    }
}

impl<FC: FieldGenericConfig> CanObserveVariable<FC, Var<FC::N>>
    for MultiField32ChallengerVariable<FC>
{
    fn observe(&mut self, builder: &mut Builder<FC>, value: Var<FC::N>) {
        self.observe_commitment(builder, [value])
    }
}

impl<FC: FieldGenericConfig> CanSampleVariable<FC, Felt<FC::F>>
    for MultiField32ChallengerVariable<FC>
{
    fn sample(&mut self, builder: &mut Builder<FC>) -> Felt<FC::F> {
        MultiField32ChallengerVariable::sample(self, builder)
    }
}

impl<FC: FieldGenericConfig> CanSampleBitsVariable<FC, Var<FC::N>>
    for MultiField32ChallengerVariable<FC>
{
    fn sample_bits(&mut self, builder: &mut Builder<FC>, bits: usize) -> Vec<Var<FC::N>> {
        MultiField32ChallengerVariable::sample_bits(self, builder, bits)
    }
}

impl<FC: FieldGenericConfig> FieldChallengerVariable<FC, Var<FC::N>>
    for MultiField32ChallengerVariable<FC>
{
    fn sample_ext(&mut self, builder: &mut Builder<FC>) -> Ext<FC::F, FC::EF> {
        MultiField32ChallengerVariable::sample_ext(self, builder)
    }

    fn check_witness(&mut self, builder: &mut Builder<FC>, bits: usize, witness: Felt<FC::F>) {
        MultiField32ChallengerVariable::check_witness(self, builder, bits, witness);
    }

    fn duplexing(&mut self, builder: &mut Builder<FC>) {
        MultiField32ChallengerVariable::duplexing(self, builder);
    }
}

pub fn reduce_32<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    vals: &[Felt<FC::F>],
) -> Var<FC::N> {
    let mut power = FC::N::ONE;
    let result: Var<FC::N> = builder.eval(FC::N::ZERO);
    for val in vals.iter() {
        let val = builder.felt2var_circuit(*val);
        builder.assign(result, result + val * power);
        power *= FC::N::from_canonical_u64(1u64 << 32);
    }
    result
}

pub fn split_32<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    val: Var<FC::N>,
    n: usize,
) -> Vec<Felt<FC::F>> {
    let bits = builder.num2bits_v_circuit(val, 256);
    let mut results = Vec::new();
    for i in 0..n {
        let result: Felt<FC::F> = builder.eval(FC::F::ZERO);
        for j in 0..64 {
            let bit = bits[i * 64 + j];
            let t = builder.eval(result + FC::F::from_wrapped_u64(1 << j));
            let z = builder.select_f(bit, t, result);
            builder.assign(result, z);
        }
        results.push(result);
    }
    results
}
