use super::{
    challenger::{CanObserveVariable, CanSampleBitsVariable, FieldChallengerVariable},
    config::{CircuitConfig, FieldFriConfigVariable},
    types::{FriChallengesVariable, FriProofVariable, QueryProofVariable, TwoAdicPcsRoundVariable},
};
use crate::{
    compiler::recursion::ir::{Builder, DslIr, Ext, Felt, SymbolicExt},
    configs::config::SimpleFriConfig,
    instances::configs::{recur_config as rcf, recur_kb_config as rcf_kb},
    primitives::consts::DIGEST_SIZE,
};
use itertools::{izip, Itertools};
use p3_baby_bear::BabyBear;
use p3_commit::PolynomialSpace;
use p3_field::{Field, FieldAlgebra, TwoAdicField};
use p3_fri::{BatchOpening, CommitPhaseProofStep, FriProof, QueryProof};
use p3_koala_bear::KoalaBear;
use p3_symmetric::Hash;
use p3_util::log2_strict_usize;
use std::{
    cmp::Reverse,
    iter::{once, repeat_with, zip},
};

#[derive(Debug, Clone, Copy)]
pub struct PolynomialShape {
    pub width: usize,
    pub log_degree: usize,
}

#[derive(Debug, Clone)]
pub struct PolynomialBatchShape {
    pub shapes: Vec<PolynomialShape>,
}

pub fn verify_shape_and_sample_challenges<
    CC: CircuitConfig<F = SC::Val>,
    SC: FieldFriConfigVariable<CC>,
>(
    builder: &mut Builder<CC>,
    config: &SimpleFriConfig,
    proof: &FriProofVariable<CC, SC>,
    challenger: &mut SC::FriChallengerVariable,
) -> FriChallengesVariable<CC> {
    let betas = proof
        .commit_phase_commits
        .iter()
        .map(|commitment| {
            challenger.observe(builder, *commitment);
            challenger.sample_ext(builder)
        })
        .collect();

    // Observe the final polynomial.
    let final_poly_felts = CC::ext2felt(builder, proof.final_poly);
    final_poly_felts.iter().for_each(|felt| {
        challenger.observe(builder, *felt);
    });

    assert_eq!(proof.query_proofs.len(), config.num_queries);
    challenger.check_witness(builder, config.proof_of_work_bits, proof.pow_witness);

    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    let query_indices: Vec<Vec<CC::Bit>> =
        repeat_with(|| challenger.sample_bits(builder, log_max_height))
            .take(config.num_queries)
            .collect();

    FriChallengesVariable {
        query_indices,
        betas,
    }
}

pub fn verify_two_adic_pcs<CC: CircuitConfig<F = SC::Val>, SC: FieldFriConfigVariable<CC>>(
    builder: &mut Builder<CC>,
    config: &SimpleFriConfig,
    proof: &FriProofVariable<CC, SC>,
    challenger: &mut SC::FriChallengerVariable,
    rounds: Vec<TwoAdicPcsRoundVariable<CC, SC, SC::Domain>>,
) where
    CC::F: TwoAdicField,
{
    // observe polynomial evals to avoid a security loophole
    // see: https://github.com/succinctlabs/sp1/security/advisories/GHSA-c873-wfhp-wx5m
    for round in &rounds {
        for mat in &round.domains_points_and_opens {
            for point in &mat.values {
                for coord in point {
                    let point_felts = CC::ext2felt(builder, *coord);
                    point_felts.iter().for_each(|felt| {
                        challenger.observe(builder, *felt);
                    });
                }
            }
        }
    }

    let alpha = challenger.sample_ext(builder);

    let fri_challenges =
        verify_shape_and_sample_challenges::<CC, SC>(builder, config, proof, challenger);

    let log_global_max_height = proof.commit_phase_commits.len() + config.log_blowup;

    // Precompute the two-adic powers of the two-adic generator. They can be loaded in as constants.
    // The ith element has order 2^(log_global_max_height - i).
    let mut precomputed_generator_powers: Vec<Felt<_>> = vec![];
    for i in 0..log_global_max_height + 1 {
        precomputed_generator_powers
            .push(builder.constant(CC::F::two_adic_generator(log_global_max_height - i)));
    }

    // The powers of alpha, where the ith element is alpha^i.
    let mut alpha_pows: Vec<Ext<CC::F, CC::EF>> =
        vec![builder.eval(SymbolicExt::from_f(CC::EF::ONE))];

    let reduced_openings = proof
        .query_proofs
        .iter()
        .zip(&fri_challenges.query_indices)
        .map(|(query_opening, index_bits)| {
            // The powers of alpha, where the ith element is alpha^i.
            let mut log_height_pow = [0usize; 32];
            let mut ro: [Ext<CC::F, CC::EF>; 32] =
                [builder.eval(SymbolicExt::from_f(CC::EF::ZERO)); 32];

            for (batch_opening, round) in zip(&query_opening.input_proof, rounds.iter().cloned()) {
                let batch_commit = round.batch_commit;
                let mats = round.domains_points_and_opens;
                let batch_heights = mats
                    .iter()
                    .map(|mat| mat.domain.size() << config.log_blowup)
                    .collect_vec();

                let batch_max_height = batch_heights.iter().max().expect("Empty batch?");
                let log_batch_max_height = log2_strict_usize(*batch_max_height);
                let bits_reduced = log_global_max_height - log_batch_max_height;

                let reduced_index_bits = &index_bits[bits_reduced..];

                verify_batch::<CC, SC>(
                    builder,
                    batch_commit,
                    &batch_heights,
                    reduced_index_bits,
                    batch_opening.opened_values.clone(),
                    batch_opening.opening_proof.clone(),
                );

                for (mat_opening, mat) in izip!(&batch_opening.opened_values, mats) {
                    let mat_domain = mat.domain;
                    let mat_points = mat.points;
                    let mat_values = mat.values;
                    let log_height = log2_strict_usize(mat_domain.size()) + config.log_blowup;

                    let bits_reduced = log_global_max_height - log_height;
                    let reduced_index_bits_trunc =
                        index_bits[bits_reduced..(bits_reduced + log_height)].to_vec();

                    let g = builder.generator();
                    let two_adic_generator_exp = CC::exp_f_bits_precomputed(
                        builder,
                        &reduced_index_bits_trunc.into_iter().rev().collect_vec(),
                        &precomputed_generator_powers[bits_reduced..],
                    );

                    // Unroll the following to avoid symbolic expression overhead
                    // let x: Felt<_> = builder.eval(g * two_adic_generator_exp);
                    let x: Felt<_> = builder.uninit();
                    builder.push_op(DslIr::MulF(x, g, two_adic_generator_exp));

                    for (z, ps_at_z) in izip!(mat_points, mat_values) {
                        // Unroll the loop calculation to avoid symbolic expression overhead

                        let len = ps_at_z.len();
                        let mut alphas = Vec::with_capacity(len);
                        let mut p_at_zs = Vec::with_capacity(len);
                        let mut p_at_xs = Vec::with_capacity(len);

                        // let mut acc: Ext<CC::F, CC::EF> = builder.constant(CC::EF::ZERO);
                        // let mut acc: Ext<_, _> = builder.uninit();

                        // builder.push_op(DslIr::ImmE(acc, CC::EF::ZERO));
                        for (p_at_x, p_at_z) in izip!(mat_opening.clone(), ps_at_z) {
                            let pow = log_height_pow[log_height];
                            // Fill in any missing powers of alpha.
                            for _ in alpha_pows.len()..pow + 1 {
                                // let new_alpha = builder.eval(*alpha_pows.last().unwrap() *
                                // alpha);
                                let new_alpha: Ext<_, _> = builder.uninit();
                                builder.push_op(DslIr::MulE(
                                    new_alpha,
                                    *alpha_pows.last().unwrap(),
                                    alpha,
                                ));
                                builder.reduce_e(new_alpha);
                                alpha_pows.push(new_alpha);
                            }
                            // Unroll:
                            //
                            // acc = builder.eval(acc + (alpha_pows[pow] * (p_at_z - p_at_x[0])));

                            // // let temp_1 = p_at_z - p_at_x[0];
                            // let temp_1: Ext<_, _> = builder.uninit();
                            // builder.push_op(DslIr::SubEF(temp_1, p_at_z, p_at_x[0]));
                            // // let temp_2 = alpha_pows[pow] * temp_1;
                            // let temp_2: Ext<_, _> = builder.uninit();
                            // builder.push_op(DslIr::MulE(temp_2, alpha_pows[pow], temp_1));
                            // // let temp_3 = acc + temp_2;
                            // let temp_3: Ext<_, _> = builder.uninit();
                            // builder.push_op(DslIr::AddE(temp_3, acc, temp_2));
                            // // acc = temp_3;
                            // acc = temp_3;

                            alphas.push(alpha_pows[pow]);
                            p_at_zs.push(p_at_z);
                            p_at_xs.push(p_at_x[0]);

                            log_height_pow[log_height] += 1;
                        }
                        // Unroll this calculation to avoid symbolic expression overhead
                        // ro[log_height] = builder.eval(ro[log_height] + acc / (z - x));

                        let acc = CC::batch_fri(builder, alphas, p_at_zs, p_at_xs);

                        // let temp_1 = z - x;
                        let temp_1: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::SubEF(temp_1, z, x));

                        // let temp_2 = acc / (temp_1);
                        let temp_2: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::DivE(temp_2, acc, temp_1));

                        // let temp_3 = rp[log_height] + temp_2;
                        let temp_3: Ext<_, _> = builder.uninit();
                        builder.push_op(DslIr::AddE(temp_3, ro[log_height], temp_2));

                        // ro[log_height] = temp_3;
                        ro[log_height] = temp_3;
                    }
                }
            }
            ro
        })
        .collect::<Vec<_>>();

    verify_challenges::<CC, SC>(
        builder,
        config,
        proof.clone(),
        &fri_challenges,
        reduced_openings,
    );
}

pub fn verify_challenges<CC: CircuitConfig<F = SC::Val>, SC: FieldFriConfigVariable<CC>>(
    builder: &mut Builder<CC>,
    config: &SimpleFriConfig,
    proof: FriProofVariable<CC, SC>,
    challenges: &FriChallengesVariable<CC>,
    reduced_openings: Vec<[Ext<CC::F, CC::EF>; 32]>,
) where
    SC::Val: p3_field::TwoAdicField,
{
    let log_max_height = proof.commit_phase_commits.len() + config.log_blowup;
    for ((index_bits, query_proof), ro) in challenges
        .query_indices
        .iter()
        .zip(proof.query_proofs)
        .zip(reduced_openings)
    {
        let folded_eval = verify_query::<CC, SC>(
            builder,
            &proof.commit_phase_commits,
            index_bits,
            query_proof,
            &challenges.betas,
            ro,
            log_max_height,
        );

        builder.assert_ext_eq(folded_eval, proof.final_poly);
    }
}

pub fn verify_query<CC: CircuitConfig<F = SC::Val>, SC: FieldFriConfigVariable<CC>>(
    builder: &mut Builder<CC>,
    commit_phase_commits: &[SC::DigestVariable],
    index_bits: &[CC::Bit],
    proof: QueryProofVariable<CC, SC>,
    betas: &[Ext<CC::F, CC::EF>],
    reduced_openings: [Ext<CC::F, CC::EF>; 32],
    log_max_height: usize,
) -> Ext<CC::F, CC::EF>
where
    CC::F: TwoAdicField,
{
    let mut folded_eval: Ext<_, _> = builder.constant(CC::EF::ZERO);
    let two_adic_generator: Felt<_> = builder.constant(CC::F::two_adic_generator(log_max_height));

    // TODO: fix expreversebits address bug to avoid needing to allocate a new variable.
    let mut x = CC::exp_reverse_bits(
        builder,
        two_adic_generator,
        index_bits[..log_max_height].to_vec(),
    );

    for (offset, log_folded_height, commit, step, beta) in izip!(
        0..,
        (0..log_max_height).rev(),
        commit_phase_commits,
        &proof.commit_phase_openings,
        betas,
    ) {
        folded_eval = builder.eval(folded_eval + reduced_openings[log_folded_height + 1]);

        let index_sibling_complement: CC::Bit = index_bits[offset];
        let index_pair = &index_bits[(offset + 1)..];

        builder.reduce_e(folded_eval);

        let evals_ext = CC::select_chain_ef(
            builder,
            index_sibling_complement,
            once(folded_eval),
            once(step.sibling_value),
        );
        let evals_felt = vec![
            CC::ext2felt(builder, evals_ext[0]).to_vec(),
            CC::ext2felt(builder, evals_ext[1]).to_vec(),
        ];

        let heights = &[1 << log_folded_height];
        verify_batch::<CC, SC>(
            builder,
            *commit,
            heights,
            index_pair,
            [evals_felt].to_vec(),
            step.opening_proof.clone(),
        );

        let xs_new: Felt<_> = builder.eval(x * CC::F::two_adic_generator(1));
        let xs = CC::select_chain_f(builder, index_sibling_complement, once(x), once(xs_new));

        // Unroll the `folded_eval` calculation to avoid symbolic expression overhead.
        // folded_eval = builder
        //     .eval(evals_ext[0] + (beta - xs[0]) * (evals_ext[1] - evals_ext[0]) / (xs[1] -
        // xs[0])); x = builder.eval(x * x);

        // let temp_1 = xs[1] - xs[0];
        let temp_1: Felt<_> = builder.uninit();
        builder.push_op(DslIr::SubF(temp_1, xs[1], xs[0]));

        // let temp_2 = evals_ext[1] - evals_ext[0];
        let temp_2: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::SubE(temp_2, evals_ext[1], evals_ext[0]));

        // let temp_3 = temp_2 / temp_1;
        let temp_3: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::DivEF(temp_3, temp_2, temp_1));

        // let temp_4 = beta - xs[0];
        let temp_4: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::SubEF(temp_4, *beta, xs[0]));

        // let temp_5 = temp_4 * temp_3;
        let temp_5: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::MulE(temp_5, temp_4, temp_3));

        // let temp65 = evals_ext[0] + temp_5;
        let temp_6: Ext<_, _> = builder.uninit();
        builder.push_op(DslIr::AddE(temp_6, evals_ext[0], temp_5));
        // folded_eval = temp_6;
        folded_eval = temp_6;

        // let temp_7 = x * x;
        let temp_7: Felt<_> = builder.uninit();
        builder.push_op(DslIr::MulF(temp_7, x, x));
        // x = temp_7;
        x = temp_7;
    }

    folded_eval
}

pub fn verify_batch<CC: CircuitConfig<F = SC::Val>, SC: FieldFriConfigVariable<CC>>(
    builder: &mut Builder<CC>,
    commit: SC::DigestVariable,
    heights: &[usize],
    index_bits: &[CC::Bit],
    opened_values: Vec<Vec<Vec<Felt<CC::F>>>>,
    proof: Vec<SC::DigestVariable>,
) {
    let mut heights_tallest_first = heights
        .iter()
        .enumerate()
        .sorted_by_key(|(_, height)| Reverse(*height))
        .peekable();

    let mut curr_height_padded = heights_tallest_first.peek().unwrap().1.next_power_of_two();

    let ext_slice: Vec<Vec<Felt<CC::F>>> = heights_tallest_first
        .peeking_take_while(|(_, height)| height.next_power_of_two() == curr_height_padded)
        .flat_map(|(i, _)| opened_values[i].as_slice())
        .cloned()
        .collect::<Vec<_>>();
    let felt_slice: Vec<Felt<CC::F>> = ext_slice.into_iter().flatten().collect::<Vec<_>>();
    let mut root: SC::DigestVariable = SC::hash(builder, &felt_slice[..]);

    zip(index_bits.iter(), proof).for_each(|(&bit, sibling): (&CC::Bit, SC::DigestVariable)| {
        let compress_args = SC::select_chain_digest(builder, bit, [root, sibling]);

        root = SC::compress(builder, compress_args);
        curr_height_padded >>= 1;

        let next_height = heights_tallest_first
            .peek()
            .map(|(_, height)| *height)
            .filter(|h| h.next_power_of_two() == curr_height_padded);

        if let Some(next_height) = next_height {
            let ext_slice: Vec<Vec<Felt<CC::F>>> = heights_tallest_first
                .peeking_take_while(|(_, height)| *height == next_height)
                .flat_map(|(i, _)| opened_values[i].clone())
                .collect::<Vec<_>>();
            let felt_slice: Vec<Felt<CC::F>> = ext_slice.into_iter().flatten().collect::<Vec<_>>();
            let next_height_openings_digest = SC::hash(builder, &felt_slice);
            root = SC::compress(builder, [root, next_height_openings_digest]);
        }
    });

    SC::assert_digest_eq(builder, root, commit);
}

pub fn dummy_hash<F: Field>() -> Hash<F, F, DIGEST_SIZE> {
    [F::ZERO; DIGEST_SIZE].into()
}

macro_rules! dummy_query_proof_fn {
    // Accepts the rcf name as the input argument and generates the function
    ($rcf:ident, $func_name:ident) => {
        // Generated function for the specific rcf
        pub fn $func_name(
            height: usize,
            log_blowup: usize,
            batch_shapes: &[PolynomialBatchShape],
        ) -> QueryProof<$rcf::SC_Challenge, $rcf::SC_ChallengeMmcs, Vec<$rcf::SC_BatchOpening>> {
            QueryProof {
                input_proof: batch_shapes
                    .iter()
                    .map(|shapes| {
                        let batch_max_height = shapes
                            .shapes
                            .iter()
                            .map(|shape| shape.log_degree)
                            .max()
                            .unwrap();

                        BatchOpening {
                            opened_values: shapes
                                .shapes
                                .iter()
                                .map(|shape| vec![$rcf::SC_Val::ZERO; shape.width])
                                .collect(),
                            opening_proof: vec![
                                dummy_hash::<$rcf::SC_Val>().into();
                                batch_max_height + log_blowup
                            ],
                        }
                    })
                    .collect::<Vec<_>>(),
                commit_phase_openings: (0..height)
                    .map(|i| CommitPhaseProofStep {
                        sibling_value: $rcf::SC_Challenge::ZERO,
                        opening_proof: vec![
                            dummy_hash::<$rcf::SC_Val>().into();
                            height - i + log_blowup - 1
                        ],
                    })
                    .collect(),
            }
        }
    };
}

// Call the macro to generate the functions for the `rcf` and `rcf_kb` rcfs
dummy_query_proof_fn!(rcf, dummy_query_proof); // Generates dummy_query_proof_rcf function
dummy_query_proof_fn!(rcf_kb, dummy_query_proof_kb); // Generates dummy_query_proof_rcf_kb function

/// Macro to generate dummy PCS proof functions for different modules
macro_rules! dummy_pcs_proof_fn {
    ($func_name:ident, $module:ident, $field:ty, $query_proof_fn:ident) => {
        pub fn $func_name(
            fri_queries: usize,
            batch_shapes: &[PolynomialBatchShape],
            log_blowup: usize,
        ) -> $module::SC_PcsProof {
            let max_height = batch_shapes
                .iter()
                .map(|shape| {
                    shape
                        .shapes
                        .iter()
                        .map(|shape| shape.log_degree)
                        .max()
                        .unwrap()
                })
                .max()
                .unwrap();

            FriProof {
                commit_phase_commits: vec![dummy_hash::<$field>(); max_height],
                query_proofs: vec![
                    $query_proof_fn(max_height, log_blowup, batch_shapes);
                    fri_queries
                ],
                final_poly: $module::SC_Challenge::ZERO,
                pow_witness: $module::SC_Val::ZERO,
            }
        }
    };
}

// Generate the functions for `rcf` and `rcf_kb` modules
dummy_pcs_proof_fn!(dummy_pcs_proof_bb, rcf, BabyBear, dummy_query_proof);
dummy_pcs_proof_fn!(dummy_pcs_proof_kb, rcf_kb, KoalaBear, dummy_query_proof_kb);
