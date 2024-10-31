use super::{
    keys::BaseVerifyingKeyVariable,
    p3::{
        challenger::DuplexChallengerVariable,
        fri::{types::FriConfigVariable, TwoAdicMultiplicativeCosetVariable},
    },
    stark::EMPTY,
};
use crate::{
    compiler::recursion::ir::{Array, Builder, Felt, Var},
    configs::config::{FieldGenericConfig, StarkGenericConfig},
    instances::configs::recur_config as rcf,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        proof::{BaseProof, QuotientData},
        utils::order_chips,
    },
    primitives::consts::DIGEST_SIZE,
    recursion::{air::ChallengerPublicValues, runtime::PERMUTATION_WIDTH},
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, TwoAdicField};
use p3_fri::FriConfig;

pub fn const_fri_config(
    builder: &mut Builder<rcf::FieldConfig>,
    config: &FriConfig<rcf::ChallengeMmcs>,
) -> FriConfigVariable<rcf::FieldConfig> {
    let two_addicity = rcf::Val::TWO_ADICITY;
    let mut generators = builder.dyn_array(two_addicity);
    let mut subgroups = builder.dyn_array(two_addicity);
    for i in 0..two_addicity {
        let constant_generator = rcf::Val::two_adic_generator(i);
        builder.set(&mut generators, i, constant_generator);

        let constant_domain = TwoAdicMultiplicativeCoset {
            log_n: i,
            shift: rcf::Val::one(),
        };
        let domain_value: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(constant_domain);
        builder.set(&mut subgroups, i, domain_value);
    }
    FriConfigVariable {
        log_blowup: builder.eval(BabyBear::from_canonical_usize(config.log_blowup)),
        blowup: builder.eval(BabyBear::from_canonical_usize(1 << config.log_blowup)),
        num_queries: builder.eval(BabyBear::from_canonical_usize(config.num_queries)),
        proof_of_work_bits: builder.eval(BabyBear::from_canonical_usize(config.proof_of_work_bits)),
        subgroups,
        generators,
    }
}

// OPT: this can be done much more efficiently, but in the meantime this should work
pub fn felt2var<RC: FieldGenericConfig>(
    builder: &mut Builder<RC>,
    felt: Felt<RC::F>,
) -> Var<RC::N> {
    let bits = builder.num2bits_f(felt);
    builder.bits2num_v(&bits)
}

pub fn var2felt<RC: FieldGenericConfig>(builder: &mut Builder<RC>, var: Var<RC::N>) -> Felt<RC::F> {
    let bits = builder.num2bits_v(var);
    builder.bits2num_f(&bits)
}

/// Asserts that the challenger variable is equal to a challenger in public values.
pub fn assert_challenger_eq_pv<RC: FieldGenericConfig>(
    builder: &mut Builder<RC>,
    var: &DuplexChallengerVariable<RC>,
    values: ChallengerPublicValues<Felt<RC::F>>,
) {
    for i in 0..PERMUTATION_WIDTH {
        let element = builder.get(&var.sponge_state, i);
        builder.assert_felt_eq(element, values.sponge_state[i]);
    }
    let num_inputs_var = felt2var(builder, values.num_inputs);
    builder.assert_var_eq(var.nb_inputs, num_inputs_var);
    let mut input_buffer_array: Array<_, Felt<_>> = builder.dyn_array(PERMUTATION_WIDTH);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut input_buffer_array, i, values.input_buffer[i]);
    }
    builder.range(0, num_inputs_var).for_each(|i, builder| {
        let element = builder.get(&var.input_buffer, i);
        let values_element = builder.get(&input_buffer_array, i);
        builder.assert_felt_eq(element, values_element);
    });
    let num_outputs_var = felt2var(builder, values.num_outputs);
    builder.assert_var_eq(var.nb_outputs, num_outputs_var);
    let mut output_buffer_array: Array<_, Felt<_>> = builder.dyn_array(PERMUTATION_WIDTH);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut output_buffer_array, i, values.output_buffer[i]);
    }
    builder.range(0, num_outputs_var).for_each(|i, builder| {
        let element = builder.get(&var.output_buffer, i);
        let values_element = builder.get(&output_buffer_array, i);
        builder.assert_felt_eq(element, values_element);
    });
}

/// Assigns a challenger variable from a challenger in public values.
pub fn assign_challenger_from_pv<RC: FieldGenericConfig>(
    builder: &mut Builder<RC>,
    dst: &mut DuplexChallengerVariable<RC>,
    values: ChallengerPublicValues<Felt<RC::F>>,
) {
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.sponge_state, i, values.sponge_state[i]);
    }
    let num_inputs_var = felt2var(builder, values.num_inputs);
    builder.assign(dst.nb_inputs, num_inputs_var);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.input_buffer, i, values.input_buffer[i]);
    }
    let num_outputs_var = felt2var(builder, values.num_outputs);
    builder.assign(dst.nb_outputs, num_outputs_var);
    for i in 0..PERMUTATION_WIDTH {
        builder.set(&mut dst.output_buffer, i, values.output_buffer[i]);
    }
}

pub fn get_challenger_public_values<RC: FieldGenericConfig>(
    builder: &mut Builder<RC>,
    var: &DuplexChallengerVariable<RC>,
) -> ChallengerPublicValues<Felt<RC::F>> {
    let sponge_state = core::array::from_fn(|i| builder.get(&var.sponge_state, i));
    let num_inputs = var2felt(builder, var.nb_inputs);
    let input_buffer = core::array::from_fn(|i| builder.get(&var.input_buffer, i));
    let num_outputs = var2felt(builder, var.nb_outputs);
    let output_buffer = core::array::from_fn(|i| builder.get(&var.output_buffer, i));

    ChallengerPublicValues {
        sponge_state,
        num_inputs,
        input_buffer,
        num_outputs,
        output_buffer,
    }
}

/// Hash the verifying key + prep domains into a single digest.
/// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
pub fn hash_vkey<RC: FieldGenericConfig>(
    builder: &mut Builder<RC>,
    vk: &BaseVerifyingKeyVariable<RC>,
) -> Array<RC, Felt<RC::F>> {
    let domain_slots: Var<_> = builder.eval(vk.preprocessed_domains.len() * 4);
    let vkey_slots: Var<_> = builder.constant(RC::N::from_canonical_usize(DIGEST_SIZE + 1));
    let total_slots: Var<_> = builder.eval(vkey_slots + domain_slots);
    let mut inputs = builder.dyn_array(total_slots);
    builder.range(0, DIGEST_SIZE).for_each(|i, builder| {
        let element = builder.get(&vk.commitment, i);
        builder.set(&mut inputs, i, element);
    });
    builder.set(&mut inputs, DIGEST_SIZE, vk.pc_start);
    let four: Var<_> = builder.constant(RC::N::from_canonical_usize(4));
    let one: Var<_> = builder.constant(RC::N::one());
    builder
        .range(0, vk.preprocessed_domains.len())
        .for_each(|i, builder| {
            let sorted_index = builder.get(&vk.preprocessed_sorted_idxs, i);
            let domain = builder.get(&vk.preprocessed_domains, i);
            let log_n_index: Var<_> = builder.eval(vkey_slots + sorted_index * four);
            let size_index: Var<_> = builder.eval(log_n_index + one);
            let shift_index: Var<_> = builder.eval(size_index + one);
            let g_index: Var<_> = builder.eval(shift_index + one);
            let log_n_felt = var2felt(builder, domain.log_n);
            let size_felt = var2felt(builder, domain.size);
            builder.set(&mut inputs, log_n_index, log_n_felt);
            builder.set(&mut inputs, size_index, size_felt);
            builder.set(&mut inputs, shift_index, domain.shift);
            builder.set(&mut inputs, g_index, domain.g);
        });
    builder.poseidon2_hash(&inputs)
}

pub(crate) fn get_sorted_indices<SC, C>(
    chips: &[MetaChip<SC::Val, C>],
    proof: &BaseProof<SC>,
) -> Vec<usize>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    chips
        .iter()
        .map(|chip| proof.main_chip_ordering.get(&chip.name()).copied())
        .into_iter()
        .map(|x| x.unwrap_or_else(|| EMPTY))
        .collect()
}

pub(crate) fn get_preprocessed_data<SC, A>(
    chips: &[MetaChip<SC::Val, A>],
    preprocessed_chip_ids: &[usize],
    vk: &BaseVerifyingKey<SC>,
) -> (Vec<usize>, Vec<SC::Domain>)
where
    SC: StarkGenericConfig,
    A: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    let (prep_sorted_indices, prep_domains) = preprocessed_chip_ids
        .into_iter()
        .map(|&chip_idx| {
            let name = chips[chip_idx].name().clone();
            let prep_sorted_idx = vk.preprocessed_chip_ordering[&name];
            (prep_sorted_idx, vk.preprocessed_info[prep_sorted_idx].1)
        })
        .unzip();
    (prep_sorted_indices, prep_domains)
}

pub(crate) fn get_chip_quotient_data<SC, C>(
    chips: &[MetaChip<SC::Val, C>],
    proof: &BaseProof<SC>,
) -> Vec<QuotientData>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    order_chips::<SC, C>(chips, proof.main_chip_ordering.clone())
        .into_iter()
        .map(|chip| {
            let log_quotient_degree = chip.get_log_quotient_degree();
            QuotientData {
                log_quotient_degree,
                quotient_size: 1 << log_quotient_degree,
            }
        })
        .collect()
}
