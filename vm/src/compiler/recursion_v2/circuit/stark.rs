use super::{
    builder::CircuitV2Builder,
    challenger::CanObserveVariable,
    config::{BabyBearFriConfigVariable, CircuitConfig},
    hash::FieldHasherVariable,
    types::{BaseVerifyingKeyVariable, TwoAdicPcsMatsVariable, TwoAdicPcsRoundVariable},
};
use crate::compiler::recursion_v2::circuit::types::FriProofVariable;
use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::FieldChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
            domain::PolynomialSpaceVariable, fri::verify_two_adic_pcs,
        },
        ir::{Ext, Felt},
        prelude::*,
    },
    configs::config::{Challenger, FieldGenericConfig, StarkGenericConfig, Val},
    instances::configs::riscv_config::StarkConfig as RiscvSC,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{
            // todo: use v2
            ProverConstraintFolder,
            VerifierConstraintFolder,
        },
        keys::BaseVerifyingKey,
        lookup::LookupScope,
        machine::BaseMachine,
        proof::{BaseCommitments, BaseOpenedValues},
        utils::order_chips,
    },
};
use hashbrown::HashMap;
use itertools::{izip, Itertools};
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_commit::{Mmcs, Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{ExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

/// Reference: [pico_machine::stark::BaseProof]
#[derive(Clone)]
pub struct BaseProofVariable<CC: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<CC>> {
    pub commitments: BaseCommitments<SC::DigestVariable>,
    pub opened_values: BaseOpenedValues<Ext<CC::F, CC::EF>>,
    pub opening_proof: FriProofVariable<CC, SC>,
    pub log_main_degrees: Vec<usize>,
    pub log_quotient_degrees: Vec<usize>,
    pub main_chip_ordering: HashMap<String, usize>,
    pub public_values: Vec<Felt<CC::F>>,
}

/// Get a dummy duplex challenger for use in dummy proofs.
pub fn dummy_challenger(config: &RiscvSC) -> Challenger<RiscvSC> {
    let mut challenger = config.challenger();
    challenger.input_buffer = vec![];
    challenger.output_buffer = vec![BabyBear::ZERO; challenger.sponge_state.len()];
    challenger
}

// TODO: other dummy_xxxx

#[derive(Clone)]
pub struct MerkleProofVariable<CC: CircuitConfig, HV: FieldHasherVariable<CC>> {
    pub index: Vec<CC::Bit>,
    pub path: Vec<HV::DigestVariable>,
}

pub const EMPTY: usize = 0x_1111_1111;

#[derive(Debug, Clone, Copy)]
pub struct StarkVerifier<FC: FieldGenericConfig, SC: StarkGenericConfig, A> {
    _phantom: std::marker::PhantomData<(FC, SC, A)>,
}

impl<CC, SC, A> StarkVerifier<CC, SC, A>
where
    CC::F: TwoAdicField,
    CC: CircuitConfig<F = SC::Val>,
    SC: BabyBearFriConfigVariable<CC>,
    <SC::ValMmcs as Mmcs<BabyBear>>::ProverData<RowMajorMatrix<BabyBear>>: Clone,
    A: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    pub fn natural_domain_for_degree(
        config: &SC,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<CC::F> {
        <SC::Pcs as Pcs<SC::Challenge, SC::FriChallenger>>::natural_domain_for_degree(
            config.pcs(),
            degree,
        )
    }

    #[allow(unused_variables)]
    pub fn verify_chunk(
        builder: &mut Builder<CC>,
        vk: &BaseVerifyingKeyVariable<CC, SC>,
        machine: &BaseMachine<SC, A>,
        challenger: &mut SC::FriChallengerVariable,
        proof: &BaseProofVariable<CC, SC>,
        global_permutation_challenges: &[Ext<CC::F, CC::EF>],
    ) where
        A: ChipBehavior<CC::F> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
    {
        let chips = machine.chips();
        let chips = order_chips::<SC, A>(&chips, &proof.main_chip_ordering).collect_vec();
        let chip_scopes = chips.iter().map(|chip| chip.lookup_scope()).collect_vec();

        let has_global_main_commit = chip_scopes.contains(&LookupScope::Global);

        let BaseProofVariable {
            commitments,
            opened_values,
            opening_proof,
            main_chip_ordering,
            public_values,
            ..
        } = proof;

        let log_degrees = opened_values
            .chips_opened_values
            .iter()
            .map(|val| val.log_main_degree)
            .collect_vec();

        let log_quotient_degrees = chips
            .iter()
            .map(|chip| chip.get_log_quotient_degree())
            .collect_vec();

        let trace_domains = log_degrees
            .iter()
            .map(|log_degree| Self::natural_domain_for_degree(&machine.config(), 1 << log_degree))
            .collect_vec();

        let BaseCommitments {
            global_main_commit,
            regional_main_commit,
            permutation_commit,
            quotient_commit,
        } = *commitments;

        challenger.observe(builder, regional_main_commit);

        let regional_permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(builder)).collect_vec();

        challenger.observe(builder, permutation_commit);
        for (opening, chip) in opened_values
            .chips_opened_values
            .iter()
            .zip_eq(chips.iter())
        {
            let global_sum = CC::ext2felt(builder, opening.global_cumulative_sum);
            let regional_sum = CC::ext2felt(builder, opening.regional_cumulative_sum);
            challenger.observe_slice(builder, global_sum);
            challenger.observe_slice(builder, regional_sum);

            let has_global_interactions = chip
                .looking
                .iter()
                .chain(chip.looked.iter())
                .any(|i| i.scope == LookupScope::Global);
            if !has_global_interactions {
                builder.assert_ext_eq(opening.global_cumulative_sum, CC::EF::ZERO.cons());
            }
            let has_regional_interactions = chip
                .looking
                .iter()
                .chain(chip.looked.iter())
                .any(|i| i.scope == LookupScope::Regional);
            if !has_regional_interactions {
                builder.assert_ext_eq(opening.regional_cumulative_sum, CC::EF::ZERO.cons());
            }
        }

        let alpha = challenger.sample_ext(builder);

        challenger.observe(builder, quotient_commit);

        let zeta = challenger.sample_ext(builder);

        let preprocessed_domains_points_and_opens = vk
            .preprocessed_info
            .iter()
            .map(|(name, domain, _)| {
                let i = main_chip_ordering[name];
                let values = opened_values.chips_opened_values[i].clone();
                TwoAdicPcsMatsVariable::<CC> {
                    domain: *domain,
                    points: vec![zeta, domain.next_point_variable(builder, zeta)],
                    values: vec![
                        values.preprocessed_local.clone(),
                        values.preprocessed_next.clone(),
                    ],
                }
            })
            .collect_vec();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .map(|(domain, values)| TwoAdicPcsMatsVariable::<CC> {
                domain: *domain,
                points: vec![zeta, domain.next_point_variable(builder, zeta)],
                values: vec![values.main_local.clone(), values.main_next.clone()],
            })
            .collect_vec();

        let perm_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .map(|(domain, values)| TwoAdicPcsMatsVariable::<CC> {
                domain: *domain,
                points: vec![zeta, domain.next_point_variable(builder, zeta)],
                values: vec![
                    values.permutation_local.clone(),
                    values.permutation_next.clone(),
                ],
            })
            .collect_vec();

        let quotient_chunk_domains = trace_domains
            .iter()
            .zip_eq(log_degrees)
            .zip_eq(log_quotient_degrees)
            .map(|((domain, log_degree), log_quotient_degree)| {
                let quotient_degree = 1 << log_quotient_degree;
                let quotient_domain =
                    domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree));
                quotient_domain.split_domains(quotient_degree)
            })
            .collect_vec();

        let quotient_domains_points_and_opens = proof
            .opened_values
            .chips_opened_values
            .iter()
            .zip_eq(quotient_chunk_domains.iter())
            .flat_map(|(values, qc_domains)| {
                values
                    .quotient
                    .iter()
                    .zip_eq(qc_domains)
                    .map(move |(values, q_domain)| TwoAdicPcsMatsVariable::<CC> {
                        domain: *q_domain,
                        points: vec![zeta],
                        values: vec![values.clone()],
                    })
            })
            .collect_vec();

        // Split the main_domains_points_and_opens to the global and local chips.
        let mut global_trace_points_and_openings = vec![];
        let mut regional_trace_points_and_openings = vec![];
        for (i, points_and_openings) in main_domains_points_and_opens
            .clone()
            .into_iter()
            .enumerate()
        {
            let scope = chip_scopes[i];
            if scope == LookupScope::Global {
                global_trace_points_and_openings.push(points_and_openings);
            } else {
                regional_trace_points_and_openings.push(points_and_openings);
            }
        }

        // Create the pcs rounds.
        let prep_commit = vk.commit;
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            domains_points_and_opens: preprocessed_domains_points_and_opens,
        };
        let global_main_round = TwoAdicPcsRoundVariable {
            batch_commit: global_main_commit,
            domains_points_and_opens: global_trace_points_and_openings,
        };
        let regional_main_round = TwoAdicPcsRoundVariable {
            batch_commit: regional_main_commit,
            domains_points_and_opens: regional_trace_points_and_openings,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: permutation_commit,
            domains_points_and_opens: perm_domains_points_and_opens,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: quotient_commit,
            domains_points_and_opens: quotient_domains_points_and_opens,
        };

        let rounds = if has_global_main_commit {
            vec![
                prep_round,
                global_main_round,
                regional_main_round,
                perm_round,
                quotient_round,
            ]
        } else {
            vec![prep_round, regional_main_round, perm_round, quotient_round]
        };

        // Verify the pcs proof
        builder.cycle_tracker_v2_enter("stage-d-verify-pcs".to_string());
        let config = machine.config();
        let config = config.fri_config();
        verify_two_adic_pcs::<CC, SC>(builder, config, opening_proof, challenger, rounds);
        builder.cycle_tracker_v2_exit();

        // Verify the constrtaint evaluations.
        builder.cycle_tracker_v2_enter("stage-e-verify-constraints".to_string());
        let permutation_challenges = global_permutation_challenges
            .iter()
            .chain(regional_permutation_challenges.iter())
            .copied()
            .collect::<Vec<_>>();

        for (chip, trace_domain, qc_domains, values) in izip!(
            chips.iter(),
            trace_domains,
            quotient_chunk_domains,
            opened_values.chips_opened_values.iter(),
        ) {
            // Verify the shape of the opening arguments matches the expected values.
            let valid_shape = values.preprocessed_local.len() == chip.preprocessed_width()
                && values.preprocessed_next.len() == chip.preprocessed_width()
                && values.main_local.len() == chip.width()
                && values.main_next.len() == chip.width()
                && values.permutation_local.len()
                    == chip.permutation_width()
                        * <SC::Challenge as FieldExtensionAlgebra<CC::F>>::D
                && values.permutation_next.len()
                    == chip.permutation_width()
                        * <SC::Challenge as FieldExtensionAlgebra<CC::F>>::D
                && values.quotient.len() == chip.logup_batch_size()
                && values
                    .quotient
                    .iter()
                    .all(|qc| qc.len() == <SC::Challenge as FieldExtensionAlgebra<CC::F>>::D);
            if !valid_shape {
                panic!("Invalid proof shape");
            }

            // Verify the constraint evaluation.
            Self::verify_constraints(
                builder,
                chip,
                values,
                trace_domain,
                qc_domains,
                zeta,
                alpha,
                &permutation_challenges,
                public_values,
            );
        }

        // Verify that the chips' local_cumulative_sum sum to 0.
        let regional_cumulative_sum: Ext<CC::F, CC::EF> = opened_values
            .chips_opened_values
            .iter()
            .map(|val| val.regional_cumulative_sum)
            .fold(builder.constant(CC::EF::ZERO), |acc, x| {
                builder.eval(acc + x)
            });
        let zero_ext: Ext<_, _> = builder.constant(CC::EF::ZERO);
        builder.assert_ext_eq(regional_cumulative_sum, zero_ext);

        builder.cycle_tracker_v2_exit();
    }
}

impl<CC: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<CC>> BaseProofVariable<CC, SC> {
    pub fn contains_cpu(&self) -> bool {
        self.main_chip_ordering.contains_key("Cpu")
    }

    pub fn log_degree_cpu(&self) -> usize {
        let idx = self
            .main_chip_ordering
            .get("Cpu")
            .expect("CPU chip not found");
        self.opened_values.chips_opened_values[*idx].log_main_degree
    }

    pub fn contains_memory_initialize(&self) -> bool {
        self.main_chip_ordering.contains_key("MemoryInitialize")
    }

    pub fn contains_memory_finalize(&self) -> bool {
        self.main_chip_ordering.contains_key("MemoryFinalize")
    }
}
