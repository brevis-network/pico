use super::{
    types::{
        DigestVariable, DimensionsVariable, FriConfigVariable, PcsProofVariable,
        TwoAdicPcsMatsVariable, TwoAdicPcsRoundVariable,
    },
    verify_batch, verify_challenges, verify_shape_and_sample_challenges,
    TwoAdicMultiplicativeCosetVariable,
};
use crate::{
    compiler::recursion::{
        prelude::*,
        program_builder::p3::{
            challenger::{DuplexChallengerVariable, FeltChallenger},
            commit::PcsVariable,
        },
    },
    configs::config::FieldGenericConfig,
    primitives::{consts::DIGEST_SIZE, types::RecursionProgramType},
};
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, TwoAdicField};
use p3_symmetric::Hash;

pub fn verify_two_adic_pcs<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    config: &FriConfigVariable<FC>,
    rounds: Array<FC, TwoAdicPcsRoundVariable<FC>>,
    proof: PcsProofVariable<FC>,
    challenger: &mut DuplexChallengerVariable<FC>,
) where
    FC::F: TwoAdicField,
    FC::EF: TwoAdicField,
{
    let mut input_ptr = builder.array::<FriFoldInput<_>>(1);
    let g = builder.generator();

    let log_blowup = config.log_blowup;
    let blowup = config.blowup;
    let alpha = challenger.sample_ext(builder);

    builder.cycle_tracker("stage-d-1-verify-shape-and-sample-challenges");
    let fri_challenges =
        verify_shape_and_sample_challenges(builder, config, &proof.fri_proof, challenger);
    builder.cycle_tracker("stage-d-1-verify-shape-and-sample-challenges");

    let commit_phase_commits_len = proof
        .fri_proof
        .commit_phase_commits
        .len()
        .materialize(builder);
    let log_global_max_height: Var<_> = builder.eval(commit_phase_commits_len + log_blowup);

    let mut reduced_openings: Array<FC, Array<FC, Ext<FC::F, FC::EF>>> =
        builder.array(proof.query_openings.len());

    builder.cycle_tracker("stage-d-2-fri-fold");
    builder
        .range(0, proof.query_openings.len())
        .for_each(|i, builder| {
            let query_opening = builder.get(&proof.query_openings, i);
            let index_bits = builder.get(&fri_challenges.query_indices, i);

            let mut ro: Array<FC, Ext<FC::F, FC::EF>> = builder.array(32);
            let mut alpha_pow: Array<FC, Ext<FC::F, FC::EF>> = builder.array(32);
            let zero_ef = builder.eval(FC::EF::zero().cons());
            for j in 0..32 {
                builder.set_value(&mut ro, j, zero_ef);
            }
            let one_ef = builder.eval(FC::EF::one().cons());
            for j in 0..32 {
                builder.set_value(&mut alpha_pow, j, one_ef);
            }

            builder.range(0, rounds.len()).for_each(|j, builder| {
                let batch_opening = builder.get(&query_opening, j);
                let round = builder.get(&rounds, j);
                let batch_commit = round.batch_commit;
                let mats = round.mats;

                let mut batch_heights_log2: Array<FC, Var<FC::N>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let height_log2: Var<_> = builder.eval(mat.domain.log_n + log_blowup);
                    builder.set_value(&mut batch_heights_log2, k, height_log2);
                });
                let mut batch_dims: Array<FC, DimensionsVariable<FC>> = builder.array(mats.len());
                builder.range(0, mats.len()).for_each(|k, builder| {
                    let mat = builder.get(&mats, k);
                    let dim = DimensionsVariable::<FC> {
                        height: builder.eval(mat.domain.size() * blowup),
                    };
                    builder.set_value(&mut batch_dims, k, dim);
                });

                let log_batch_max_height = builder.get(&batch_heights_log2, 0);
                let bits_reduced: Var<_> =
                    builder.eval(log_global_max_height - log_batch_max_height);
                let index_bits_shifted_v1 = index_bits.shift(builder, bits_reduced);
                verify_batch::<FC, 1>(
                    builder,
                    &batch_commit,
                    batch_dims,
                    index_bits_shifted_v1,
                    batch_opening.opened_values.clone(),
                    &batch_opening.opening_proof,
                );

                builder
                    .range(0, batch_opening.opened_values.len())
                    .for_each(|k, builder| {
                        let mat_opening = builder.get(&batch_opening.opened_values, k);
                        let mat = builder.get(&mats, k);
                        let mat_points = mat.points;
                        let mat_values = mat.values;

                        let log2_domain_size = mat.domain.log_n;
                        let log_height: Var<FC::N> = builder.eval(log2_domain_size + log_blowup);

                        let bits_reduced: Var<FC::N> =
                            builder.eval(log_global_max_height - log_height);
                        let index_bits_shifted = index_bits.shift(builder, bits_reduced);

                        let two_adic_generator = config.get_two_adic_generator(builder, log_height);
                        builder.cycle_tracker("exp_reverse_bits_len");

                        let two_adic_generator_exp: Felt<FC::F> =
                            if matches!(builder.program_type, RecursionProgramType::Embed) {
                                builder.exp_reverse_bits_len(
                                    two_adic_generator,
                                    &index_bits_shifted,
                                    log_height,
                                )
                            } else {
                                builder.exp_reverse_bits_len_fast(
                                    two_adic_generator,
                                    &index_bits_shifted,
                                    log_height,
                                )
                            };

                        builder.cycle_tracker("exp_reverse_bits_len");
                        let x: Felt<FC::F> = builder.eval(two_adic_generator_exp * g);

                        builder.range(0, mat_points.len()).for_each(|l, builder| {
                            let z: Ext<FC::F, FC::EF> = builder.get(&mat_points, l);
                            let ps_at_z: Array<
                                FC,
                                Ext<<FC as FieldGenericConfig>::F, <FC as FieldGenericConfig>::EF>,
                            > = builder.get(&mat_values, l);
                            let input = FriFoldInput {
                                z,
                                alpha,
                                x,
                                log_height,
                                mat_opening: mat_opening.clone(),
                                ps_at_z: ps_at_z.clone(),
                                alpha_pow: alpha_pow.clone(),
                                ro: ro.clone(),
                            };
                            builder.set_value(&mut input_ptr, 0, input);

                            let ps_at_z_len = ps_at_z.len().materialize(builder);
                            builder.push(DslIr::FriFold(ps_at_z_len, input_ptr.clone()));
                        });
                    });
            });

            builder.set_value(&mut reduced_openings, i, ro);
        });
    builder.cycle_tracker("stage-d-2-fri-fold");

    builder.cycle_tracker("stage-d-3-verify-challenges");
    verify_challenges(
        builder,
        config,
        &proof.fri_proof,
        &fri_challenges,
        &reduced_openings,
    );
    builder.cycle_tracker("stage-d-3-verify-challenges");
}

impl<FC: FieldGenericConfig> FromConstant<FC> for TwoAdicPcsRoundVariable<FC>
where
    FC::F: TwoAdicField,
{
    type Constant = (
        Hash<FC::F, FC::F, DIGEST_SIZE>,
        Vec<(
            TwoAdicMultiplicativeCoset<FC::F>,
            Vec<(FC::EF, Vec<FC::EF>)>,
        )>,
    );

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        let (commit_val, domains_and_openings_val) = value;

        // Allocate the commitment.
        let mut commit = builder.dyn_array::<Felt<_>>(DIGEST_SIZE);
        let commit_val: [FC::F; DIGEST_SIZE] = commit_val.into();
        for (i, f) in commit_val.into_iter().enumerate() {
            builder.set(&mut commit, i, f);
        }

        let mut mats =
            builder.dyn_array::<TwoAdicPcsMatsVariable<FC>>(domains_and_openings_val.len());

        for (i, (domain, openning)) in domains_and_openings_val.into_iter().enumerate() {
            let domain = builder.constant::<TwoAdicMultiplicativeCosetVariable<_>>(domain);

            let points_val = openning.iter().map(|(p, _)| *p).collect::<Vec<_>>();
            let values_val = openning.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>();
            let mut points: Array<_, Ext<_, _>> = builder.dyn_array(points_val.len());
            for (j, point) in points_val.into_iter().enumerate() {
                let el: Ext<_, _> = builder.eval(point.cons());
                builder.set_value(&mut points, j, el);
            }
            let mut values: Array<_, Array<_, Ext<_, _>>> = builder.dyn_array(values_val.len());
            for (j, val) in values_val.into_iter().enumerate() {
                let mut tmp = builder.dyn_array(val.len());
                for (k, v) in val.into_iter().enumerate() {
                    let el: Ext<_, _> = builder.eval(v.cons());
                    builder.set_value(&mut tmp, k, el);
                }
                builder.set_value(&mut values, j, tmp);
            }

            let mat = TwoAdicPcsMatsVariable {
                domain,
                points,
                values,
            };
            builder.set_value(&mut mats, i, mat);
        }

        Self {
            batch_commit: commit,
            mats,
        }
    }
}

#[derive(DslVariable, Clone)]
pub struct TwoAdicFriPcsVariable<FC: FieldGenericConfig> {
    pub config: FriConfigVariable<FC>,
}

impl<FC: FieldGenericConfig> PcsVariable<FC, DuplexChallengerVariable<FC>>
    for TwoAdicFriPcsVariable<FC>
where
    FC::F: TwoAdicField,
    FC::EF: TwoAdicField,
{
    type Domain = TwoAdicMultiplicativeCosetVariable<FC>;

    type Commitment = DigestVariable<FC>;

    type Proof = PcsProofVariable<FC>;

    fn natural_domain_for_log_degree(
        &self,
        builder: &mut Builder<FC>,
        log_degree: Usize<FC::N>,
    ) -> Self::Domain {
        self.config.get_subgroup(builder, log_degree)
    }

    fn verify(
        &self,
        builder: &mut Builder<FC>,
        rounds: Array<FC, TwoAdicPcsRoundVariable<FC>>,
        proof: Self::Proof,
        challenger: &mut DuplexChallengerVariable<FC>,
    ) {
        verify_two_adic_pcs(builder, &self.config, rounds, proof, challenger)
    }
}
