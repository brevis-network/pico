use super::{
    builder::CircuitV2Builder,
    challenger::CanObserveVariable,
    config::{CircuitConfig, FieldFriConfigVariable},
    hash::FieldHasherVariable,
    types::{BaseVerifyingKeyVariable, TwoAdicPcsMatsVariable, TwoAdicPcsRoundVariable},
};
use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::FieldChallengerVariable, constraints::RecursiveVerifierConstraintFolder,
            domain::PolynomialSpaceVariable, fri::verify_two_adic_pcs, types::FriProofVariable,
        },
        ir::{Ext, Felt},
        prelude::*,
    },
    configs::config::{Challenger, FieldGenericConfig, StarkGenericConfig, Val},
    instances::configs::riscv_bb_poseidon2::StarkConfig as RiscvSC,
    machine::{
        chip::ChipBehavior,
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
use p3_commit::{Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{FieldAlgebra, FieldExtensionAlgebra, TwoAdicField};

type F<FC> = <FC as FieldGenericConfig>::F;
type EF<FC> = <FC as FieldGenericConfig>::EF;
type Opening<FC> = BaseOpenedValues<Felt<F<FC>>, Ext<F<FC>, EF<FC>>>;

/// Reference: [pico_machine::stark::BaseProof]
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct BaseProofVariable<CC: CircuitConfig<F = SC::Val>, SC: FieldFriConfigVariable<CC>> {
    pub commitments: BaseCommitments<SC::DigestVariable>,
    pub opened_values: Opening<CC>,
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
    challenger.output_buffer = vec![BabyBear::ZERO; 8];
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
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
    SC::ValMmcs: Clone,
    A: ChipBehavior<Val<SC>>,
{
    pub fn natural_domain_for_degree(config: &SC, degree: usize) -> SC::Domain {
        SC::Pcs::natural_domain_for_degree(config.pcs(), degree)
    }

    #[allow(unused_variables)]
    pub fn verify_chunk(
        builder: &mut Builder<CC>,
        vk: &BaseVerifyingKeyVariable<CC, SC>,
        machine: &BaseMachine<SC, A>,
        challenger: &mut SC::FriChallengerVariable,
        proof: &BaseProofVariable<CC, SC>,
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
            main_commit,
            permutation_commit,
            quotient_commit,
        } = *commitments;

        challenger.observe(builder, main_commit);

        let regional_permutation_challenges =
            (0..2).map(|_| challenger.sample_ext(builder)).collect_vec();

        challenger.observe(builder, permutation_commit);
        for (opening, chip) in opened_values
            .chips_opened_values
            .iter()
            .zip_eq(chips.iter())
        {
            let regional_sum = CC::ext2felt(builder, opening.regional_cumulative_sum);
            let global_sum = opening.global_cumulative_sum;
            challenger.observe_slice(builder, regional_sum);
            challenger.observe_slice(builder, global_sum.0.x.0);
            challenger.observe_slice(builder, global_sum.0.y.0);

            if chip.lookup_scope() == LookupScope::Regional {
                let is_real: Felt<CC::F> = builder.uninit();
                builder.push_op(DslIr::ImmF(is_real, CC::F::ONE));
                builder.assert_digest_zero_v2(is_real, global_sum);
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
                if !chips[i].local_only() {
                    TwoAdicPcsMatsVariable::<CC, SC::Domain> {
                        domain: *domain,
                        points: vec![zeta, domain.next_point_variable(builder, zeta)],
                        values: vec![
                            opened_values.chips_opened_values[i]
                                .preprocessed_local
                                .clone(),
                            opened_values.chips_opened_values[i]
                                .preprocessed_next
                                .clone(),
                        ],
                    }
                } else {
                    TwoAdicPcsMatsVariable::<CC, SC::Domain> {
                        domain: *domain,
                        points: vec![zeta],
                        values: vec![opened_values.chips_opened_values[i]
                            .preprocessed_local
                            .clone()],
                    }
                }
            })
            .collect_vec();

        let main_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .zip_eq(chips.iter())
            .map(|((domain, values), chip)| {
                if !chip.local_only() {
                    TwoAdicPcsMatsVariable::<CC, SC::Domain> {
                        domain: *domain,
                        points: vec![zeta, domain.next_point_variable(builder, zeta)],
                        values: vec![values.main_local.clone(), values.main_next.clone()],
                    }
                } else {
                    TwoAdicPcsMatsVariable::<CC, SC::Domain> {
                        domain: *domain,
                        points: vec![zeta],
                        values: vec![values.main_local.clone()],
                    }
                }
            })
            .collect_vec();

        let perm_domains_points_and_opens = trace_domains
            .iter()
            .zip_eq(opened_values.chips_opened_values.iter())
            .map(
                |(domain, values)| TwoAdicPcsMatsVariable::<CC, SC::Domain> {
                    domain: *domain,
                    points: vec![zeta, domain.next_point_variable(builder, zeta)],
                    values: vec![
                        values.permutation_local.clone(),
                        values.permutation_next.clone(),
                    ],
                },
            )
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
                    .map(
                        move |(values, q_domain)| TwoAdicPcsMatsVariable::<CC, SC::Domain> {
                            domain: *q_domain,
                            points: vec![zeta],
                            values: vec![values.clone()],
                        },
                    )
            })
            .collect_vec();

        // Create the pcs rounds.
        let prep_commit = vk.commit;
        let prep_round = TwoAdicPcsRoundVariable {
            batch_commit: prep_commit,
            domains_points_and_opens: preprocessed_domains_points_and_opens,
        };
        let main_round = TwoAdicPcsRoundVariable {
            batch_commit: main_commit,
            domains_points_and_opens: main_domains_points_and_opens,
        };
        let perm_round = TwoAdicPcsRoundVariable {
            batch_commit: permutation_commit,
            domains_points_and_opens: perm_domains_points_and_opens,
        };
        let quotient_round = TwoAdicPcsRoundVariable {
            batch_commit: quotient_commit,
            domains_points_and_opens: quotient_domains_points_and_opens,
        };

        let rounds = vec![prep_round, main_round, perm_round, quotient_round];

        // Verify the pcs proof
        builder.cycle_tracker_v2_enter("stage-d-verify-pcs".to_string());
        let config = machine.config();
        let config = config.fri_config();
        verify_two_adic_pcs::<CC, SC>(builder, config, opening_proof, challenger, rounds);
        builder.cycle_tracker_v2_exit();

        // Verify the constrtaint evaluations.
        builder.cycle_tracker_v2_enter("stage-e-verify-constraints".to_string());
        let permutation_challenges = regional_permutation_challenges;

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

        // Verify that the chips' regional_cumulative_sum sum to 0.
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

impl<CC: CircuitConfig<F = SC::Val>, SC: FieldFriConfigVariable<CC>> BaseProofVariable<CC, SC> {
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
