//! The machines of the global-LogUp group proofs.
//!
//! The cross-chunk events of a block live in one table per chunk, plus one for the memory image.
//! Each table is committed on its own, as a cached main trace, before the block's LogUp
//! challenges `(alpha, beta)` exist. A group proof re-opens a few of those commitments under the
//! challenges and hands back the fractional sum of their rows
//! ([`verify_with_external_logup`](crate::verifier::verify_with_external_logup)); the block's
//! events balance when the sums of all its group proofs add up to zero.
//!
//! The machine for `s` tables is `s` copies of [`GlobalLogUpTableAir`], in the external LogUp
//! challenge mode. Table heights are not part of a key, so one machine serves every height.

mod binding;

use std::sync::Arc;

pub use binding::*;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::Field;

use crate::{
    air::PartitionedAirBuilder,
    builder::LookupBuilder,
    interaction::LogUpChallengeMode,
    keygen::{
        types::{MultiStarkProvingKey, MultiStarkVerifyingKeyInner},
        MultiStarkKeygenBuilder,
    },
    lookup::{LookupScope, LookupType, SymbolicLookup},
    AirRef, BaseAirWithPublicValues, PartitionedBaseAir, StarkProtocolConfig, SystemParams,
};

/// Columns of a global event table: the message `m0..m7`, the kind, and the multiplicity.
pub const TABLE_WIDTH: usize = MESSAGE_LEN + 1;
/// Elements of a global-LogUp message: `m0..m7` and the kind.
pub const MESSAGE_LEN: usize = 9;
/// The column of the multiplicity: `+1` on a send row, `-1` on a receive row, `0` on padding.
pub const MULTIPLICITY_COL: usize = MESSAGE_LEN;
/// Width of a table AIR's common main trace: one column, which no interaction reads and whose
/// value the prover sets to [`COMMON_MAIN_FILL`]. It exists because a proof cannot have a
/// zero-width common main commitment.
pub const COMMON_MAIN_WIDTH: usize = 1;
/// What the prover fills the common main column with.
pub const COMMON_MAIN_FILL: u32 = 0;
/// The most tables a group proof opens.
///
/// The GKR tree of a proof has strictly more leaves than interactions, so 16 tables of the
/// production height would double it; 15 is the most that fits the smaller tree.
pub const MAX_GROUP_LEN: usize = 15;

/// One global event table, re-read from its commitment.
///
/// The table is the AIR's cached main trace. There are no constraints: the chunk proof that
/// committed the table checked its rows. The single interaction sends each row's message with
/// the row's multiplicity on [`LookupType::GlobalLogUp`].
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalLogUpTableAir;

impl<F> BaseAirWithPublicValues<F> for GlobalLogUpTableAir {}
impl<F> PartitionedBaseAir<F> for GlobalLogUpTableAir {
    fn cached_main_widths(&self) -> Vec<usize> {
        vec![TABLE_WIDTH]
    }
    fn common_main_width(&self) -> usize {
        COMMON_MAIN_WIDTH
    }
}
impl<F> BaseAir<F> for GlobalLogUpTableAir {
    fn width(&self) -> usize {
        TABLE_WIDTH + COMMON_MAIN_WIDTH
    }
}

impl<AB: PartitionedAirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB>
    for GlobalLogUpTableAir
{
    fn eval(&self, builder: &mut AB) {
        let row = builder.cached_mains()[0].current_slice().to_vec();
        let message = row[..MESSAGE_LEN].iter().map(|&v| v.into()).collect();
        builder.looking(SymbolicLookup::new(
            message,
            row[MULTIPLICITY_COL].into(),
            LookupType::GlobalLogUp,
            LookupScope::Regional,
        ));
    }
}

/// The AIRs of the group machine for `tables` tables, all to be added as required AIRs. AIR `j`
/// reads the group's `j`-th table.
pub fn group_airs<SC: StarkProtocolConfig>(tables: usize) -> Vec<AirRef<SC>> {
    assert!(
        (1..=MAX_GROUP_LEN).contains(&tables),
        "a global-LogUp group holds 1 to {MAX_GROUP_LEN} tables, not {tables}"
    );
    (0..tables)
        .map(|_| Arc::new(GlobalLogUpTableAir) as AirRef<SC>)
        .collect()
}

/// Keygen of the group machine for `tables` tables. `config` carries [`group_params`] of the riscv
/// machine the tables come from; keygen refuses parameters that are not in the external mode's
/// terms (see `assert_external_logup_air` and the first-round radius).
pub fn group_keygen<SC: StarkProtocolConfig>(
    config: &SC,
    tables: usize,
) -> MultiStarkProvingKey<SC> {
    assert_eq!(
        config.params().logup.challenge_mode,
        LogUpChallengeMode::External,
        "a group machine is in the external LogUp challenge mode"
    );
    let mut builder = MultiStarkKeygenBuilder::new(config.clone());
    for air in group_airs::<SC>(tables) {
        builder.add_required_air(air);
    }
    builder
        .generate_pk()
        .expect("the group machine has no preprocessed trace to fail on")
}

/// The denominator of one table row's LogUp term, `alpha + h_beta(m0..m7, kind)`: the row
/// contributes `multiplicity / denominator` to its group proof's fractional sum.
///
/// `row` is a table row, or just its message; elements past the message are not read.
pub fn row_denominator<F: Field, EF: p3_field::ExtensionField<F>>(
    row: &[F],
    alpha: EF,
    beta: EF,
) -> EF {
    let mut beta_pow = EF::ONE;
    let mut fingerprint = EF::ZERO;
    for &element in &row[..MESSAGE_LEN] {
        fingerprint += beta_pow * element;
        beta_pow *= beta;
    }
    alpha + fingerprint + beta_pow * F::from_u32(LookupType::GlobalLogUp as u32 + 1)
}

/// The parameters of the group machines that go with a riscv machine at `riscv`: the same in
/// every field but the LogUp challenge mode.
///
/// They have to be the same. A group proof re-opens commitments the riscv proofs made, and a
/// commitment's layout (the stacked height, the rate, the rows per Merkle leaf) is a function of
/// the parameters it was made under.
pub fn group_params(riscv: &SystemParams) -> SystemParams {
    assert_eq!(
        riscv.logup.challenge_mode,
        LogUpChallengeMode::Internal,
        "the riscv machine draws its own LogUp challenges"
    );
    let mut params = riscv.clone();
    params.logup.challenge_mode = LogUpChallengeMode::External;
    params
}

/// Assert that `group` is a group machine key that goes with a riscv machine at `riscv`: the
/// parameters of [`group_params`], and AIRs that are exactly [`GlobalLogUpTableAir`]s.
///
/// Each AIR is held to what keygen requires of every external-mode machine
/// ([`assert_external_logup_air`](crate::keygen::assert_external_logup_air)), so a key that did
/// not come out of this build's keygen is checked in full. The rest is the shape the consumers
/// rely on: one interaction per AIR, on the group bus, sending the first [`MESSAGE_LEN`] cached
/// columns with the last one as the count.
pub fn assert_group_vk<SC: StarkProtocolConfig>(
    group: &MultiStarkVerifyingKeyInner<SC>,
    riscv: &SystemParams,
) where
    SC::F: Field,
{
    assert_eq!(
        group.params,
        group_params(riscv),
        "a group machine takes the riscv machine's parameters, in the external challenge mode"
    );
    assert!(
        riscv.first_whir_round_within_unique_decoding(),
        "the global LogUp needs a first WHIR round within the unique-decoding radius"
    );
    assert!(
        (1..=MAX_GROUP_LEN).contains(&group.per_air.len()),
        "a global-LogUp group holds 1 to {MAX_GROUP_LEN} tables"
    );
    assert!(
        group.merged_preprocessed_commit.is_none(),
        "a group machine has no preprocessed trace"
    );
    for (air_idx, vk) in group.per_air.iter().enumerate() {
        crate::keygen::assert_external_logup_air(&format!("group AIR {air_idx}"), vk);
        let width = &vk.params.width;
        assert!(
            width.preprocessed.is_none()
                && width.cached_mains == [TABLE_WIDTH]
                && width.common_main == COMMON_MAIN_WIDTH,
            "group AIR {air_idx}: unexpected trace widths {width:?}"
        );
        let [interaction] = vk.symbolic_constraints.interactions.as_slice() else {
            panic!("group AIR {air_idx}: expected exactly one interaction");
        };
        assert!(
            interaction.kind == LookupType::GlobalLogUp && interaction.count_weight == 1,
            "group AIR {air_idx}: the interaction is not a send on the group bus"
        );
        let column = |node: usize| match &vk.symbolic_constraints.constraints.nodes[node] {
            crate::air::symbolic::SymbolicExpressionNode::Variable(var) => match var.entry {
                crate::air::symbolic::symbolic_variable::Entry::Main {
                    part_index: 0,
                    offset: 0,
                } => Some(var.index),
                _ => None,
            },
            _ => None,
        };
        let message: Vec<_> = interaction.message.iter().map(|&n| column(n)).collect();
        let expected: Vec<_> = (0..MESSAGE_LEN).map(Some).collect();
        assert!(
            message == expected && column(interaction.count) == Some(MULTIPLICITY_COL),
            "group AIR {air_idx}: the interaction does not send the table's columns in order"
        );
    }
}

/// Fixtures for the group machines, shared by this crate's tests and the prover backends'.
#[cfg(any(test, feature = "test-utils"))]
pub mod fixtures {
    use std::sync::Arc;

    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        poly::matrix::ColMajorMatrix,
        prover::{
            stacked_pcs::stacked_commit, AirProvingContext, CommittedTraceData, ProvingContext,
            ReferenceColMajorBackend,
        },
    };

    /// The rows of a table of `1 << log_height` rows, of which the first `real_rows` carry a
    /// pseudo-random message and a multiplicity of `+1` or `-1`, and the rest are zero.
    pub fn table_rows<F: Field>(seed: u64, log_height: usize, real_rows: usize) -> Vec<Vec<F>> {
        let mut state = seed;
        let mut next = move || {
            // splitmix64
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        (0..1usize << log_height)
            .map(|row| {
                if row >= real_rows {
                    return vec![F::ZERO; TABLE_WIDTH];
                }
                let mut values: Vec<F> = (0..MESSAGE_LEN)
                    .map(|_| F::from_u32((next() >> 40) as u32))
                    .collect();
                values.push(if next() & 1 == 0 { F::ONE } else { -F::ONE });
                values
            })
            .collect()
    }

    /// `rows` as a column-major matrix.
    pub fn to_matrix<F: Field>(rows: &[Vec<F>]) -> ColMajorMatrix<F> {
        let width = rows[0].len();
        let values = (0..width)
            .flat_map(|col| rows.iter().map(move |row| row[col]))
            .collect();
        ColMajorMatrix::new(values, width)
    }

    /// Commit `table` on its own, the way a cached main trace is committed under `config`.
    pub fn commit_table<SC: StarkProtocolConfig>(
        config: &SC,
        table: ColMajorMatrix<SC::F>,
    ) -> CommittedTraceData<ReferenceColMajorBackend<SC>> {
        let params = config.params();
        let (commitment, data) = stacked_commit(
            config.hasher(),
            params.l_skip,
            params.n_stack,
            params.log_blowup,
            params.k_whir(),
            &[&table],
        )
        .expect("the table fits the stacked height");
        CommittedTraceData {
            commitment,
            trace: table,
            data: Arc::new(data),
        }
    }

    /// The proving context of a group proof over `tables` (in group order) under `(alpha, beta)`.
    pub fn group_proving_ctx<SC: StarkProtocolConfig>(
        tables: Vec<CommittedTraceData<ReferenceColMajorBackend<SC>>>,
        alpha: SC::EF,
        beta: SC::EF,
    ) -> ProvingContext<ReferenceColMajorBackend<SC>> {
        let per_trace = tables
            .into_iter()
            .map(|table| {
                let height = table.height();
                let common_main = ColMajorMatrix::new(
                    vec![SC::F::from_u32(COMMON_MAIN_FILL); height * COMMON_MAIN_WIDTH],
                    COMMON_MAIN_WIDTH,
                );
                AirProvingContext::new(vec![table], common_main, vec![])
            })
            .enumerate()
            .collect();
        ProvingContext::new(per_trace).with_external_logup_challenges(alpha, beta)
    }

    /// The fractional sum of `tables`' rows under `(alpha, beta)`, as a field element, and the
    /// product of all the rows' denominators.
    pub fn direct_sum<F: Field, EF: p3_field::ExtensionField<F>>(
        tables: &[Vec<Vec<F>>],
        alpha: EF,
        beta: EF,
    ) -> (EF, EF) {
        let mut sum = EF::ZERO;
        let mut product = EF::ONE;
        for row in tables.iter().flatten() {
            let denominator = row_denominator(row, alpha, beta);
            sum += denominator.inverse() * row[MULTIPLICITY_COL];
            product *= denominator;
        }
        (sum, product)
    }
}

#[cfg(test)]
mod tests {
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

    use super::{fixtures::*, *};
    use crate::{
        codec::{Decode, Encode},
        config::{
            koala_bear_poseidon2::{DuplexSponge, KoalaBearPoseidon2Config, EF, F},
            WhirProximityStrategy,
        },
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        keygen::types::MultiStarkVerifyingKey,
        proof::{Proof, EXTERNAL_LOGUP_PROOF_FLAG},
        protocol::proof_size::ProofShape,
        prover::{
            AirProvingContext, CommittedTraceData, DeviceDataTransporter, Prover, ProvingContext,
            ReferenceColMajorBackend,
        },
        test_utils::{
            dummy_airs::interaction::dummy_interaction_air::DummyInteractionAir,
            test_system_params_small,
        },
        verifier::{
            batch_constraints::BatchConstraintError, fractional_sumcheck_gkr::GkrVerificationError,
            verify, verify_with_external_logup, VerifierError,
        },
        StarkEngine,
    };

    type Sc = KoalaBearPoseidon2Config;
    type Engine = KoalaBearPoseidon2RefEngine<DuplexSponge>;
    type Table = CommittedTraceData<ReferenceColMajorBackend<Sc>>;

    /// Stands in for the riscv machine's parameters: stacked height 2^10.
    fn riscv_params() -> SystemParams {
        test_system_params_small(2, 8, 3)
    }

    fn challenges() -> (EF, EF) {
        let ef = |seed: u32| EF::from_basis_coefficients_fn(|i| F::from_u32(seed + 7 * i as u32));
        (ef(1_000_003), ef(2_000_029))
    }

    struct Group {
        engine: Engine,
        vk: MultiStarkVerifyingKey<Sc>,
        rows: Vec<Vec<Vec<F>>>,
        proof: Proof<Sc>,
    }

    /// Commit `rows` under the riscv parameters, as the chunk proofs would.
    fn commit(rows: &[Vec<Vec<F>>]) -> Vec<Table> {
        let config = Sc::default_from_params(riscv_params());
        rows.iter()
            .map(|rows| commit_table(&config, to_matrix(rows)))
            .collect()
    }

    /// Prove the group over `tables` under `(alpha, beta)`.
    fn prove_group(rows: Vec<Vec<Vec<F>>>, tables: Vec<Table>, alpha: EF, beta: EF) -> Group {
        let engine = Engine::new(group_params(&riscv_params()));
        let pk = group_keygen(engine.config(), tables.len());
        let vk = pk.get_vk();
        assert_group_vk(&vk.inner, &riscv_params());
        let d_pk = engine.device().transport_pk_to_device(&pk);
        let ctx = group_proving_ctx::<Sc>(tables, alpha, beta);
        let proof = engine.prover().prove(&d_pk, ctx).expect("group proof");
        Group {
            engine,
            vk,
            rows,
            proof,
        }
    }

    fn group(specs: &[(u64, usize, usize)], alpha: EF, beta: EF) -> Group {
        let rows: Vec<_> = specs
            .iter()
            .map(|&(seed, log_height, real)| table_rows::<F>(seed, log_height, real))
            .collect();
        let tables = commit(&rows);
        prove_group(rows, tables, alpha, beta)
    }

    fn verify_group(
        g: &Group,
        proof: &Proof<Sc>,
        alpha: EF,
        beta: EF,
    ) -> Result<(EF, EF), VerifierError<EF>> {
        verify_with_external_logup(
            g.engine.config(),
            &g.vk,
            proof,
            &mut g.engine.initial_transcript(),
            alpha,
            beta,
        )
    }

    /// A group proof verifies, and the pair it hands back is the fractional sum of the tables'
    /// rows: `p / q` equals the sum computed row by row, and `q` is the product of every row's
    /// denominator times one `alpha` per padding leaf of the GKR tree.
    #[test]
    fn group_proof_hands_back_the_fractional_sum() {
        let (alpha, beta) = challenges();
        for specs in [
            vec![(1, 6, 40)],
            vec![(2, 6, 64), (3, 6, 0), (4, 6, 17)],
            vec![(5, 7, 100), (6, 5, 32)],
        ] {
            let g = group(&specs, alpha, beta);
            let (p, q) = verify_group(&g, &g.proof, alpha, beta).expect("group proof verifies");
            let (sum, product) = direct_sum(&g.rows, alpha, beta);
            assert_eq!(p, sum * q, "p / q is not the tables' fractional sum");
            let rows: usize = g.rows.iter().map(Vec::len).sum();
            let leaves = 1usize << g.proof.gkr_proof.claims_per_layer.len();
            assert!(
                leaves > rows,
                "the GKR tree has strictly more leaves than rows"
            );
            assert_eq!(q, product * alpha.exp_u64((leaves - rows) as u64));
        }
    }

    /// Two group proofs under one `(alpha, beta)`: the second table receives what the first
    /// sends, so the two sums add up to zero, with a non-zero denominator.
    #[test]
    fn matching_groups_add_up_to_zero() {
        let (alpha, beta) = challenges();
        let sends = table_rows::<F>(11, 6, 50);
        let mut receives = sends.clone();
        receives.reverse();
        for row in &mut receives {
            row[MULTIPLICITY_COL] = -row[MULTIPLICITY_COL];
        }
        let fraction = |rows: Vec<Vec<F>>| {
            let tables = commit(std::slice::from_ref(&rows));
            let g = prove_group(vec![rows], tables, alpha, beta);
            verify_group(&g, &g.proof, alpha, beta).expect("group proof verifies")
        };
        let (p1, q1) = fraction(sends);
        let (p2, q2) = fraction(receives);
        assert_ne!(p1, EF::ZERO);
        assert_eq!(p1 * q2 + p2 * q1, EF::ZERO);
        assert_ne!(q1 * q2, EF::ZERO);
    }

    /// The premise of the whole design: one commitment, opened by two proofs. A machine in the
    /// internal mode proves over a table held in a cached main trace; a group proof then opens
    /// the same commitment and hands back that table's sum.
    #[test]
    fn one_commitment_is_opened_by_an_internal_proof_and_a_group_proof() {
        let (alpha, beta) = challenges();
        let rows = table_rows::<F>(21, 6, 64);
        let table = commit(std::slice::from_ref(&rows)).remove(0);

        // The owner: a sender and a receiver over the same table, so its own LogUp balances.
        let owner_engine = Engine::new(riscv_params());
        let airs: Vec<AirRef<Sc>> = vec![
            Arc::new(DummyInteractionAir::new(TABLE_WIDTH, true, LookupType::Byte).partition()),
            Arc::new(DummyInteractionAir::new(TABLE_WIDTH, false, LookupType::Byte).partition()),
        ];
        let (owner_pk, owner_vk) = owner_engine.keygen(&airs);
        let count = || crate::poly::matrix::ColMajorMatrix::new(vec![F::ONE; rows.len()], 1);
        let owner_ctx: ProvingContext<ReferenceColMajorBackend<Sc>> = ProvingContext::new(
            (0..2)
                .map(|air| {
                    (
                        air,
                        AirProvingContext::new(vec![table.clone()], count(), vec![]),
                    )
                })
                .collect(),
        );
        let owner_proof = owner_engine
            .prover()
            .prove(
                &owner_engine.device().transport_pk_to_device(&owner_pk),
                owner_ctx,
            )
            .expect("owner proof");
        owner_engine
            .verify(&owner_vk, &owner_proof)
            .expect("owner proof verifies");

        let g = prove_group(vec![rows], vec![table.clone()], alpha, beta);
        let (p, q) = verify_group(&g, &g.proof, alpha, beta).expect("group proof verifies");
        let (sum, _) = direct_sum(&g.rows, alpha, beta);
        assert_eq!(p, sum * q);

        let opened = |proof: &Proof<Sc>, air: usize| {
            proof.trace_vdata[air].as_ref().unwrap().cached_commitments[0]
        };
        assert_eq!(opened(&owner_proof, 0), table.commitment);
        assert_eq!(opened(&g.proof, 0), table.commitment);
    }

    /// The modes do not mix: the entry point, the key and the proof have to be of one mode.
    #[test]
    fn modes_do_not_mix() {
        let (alpha, beta) = challenges();
        let g = group(&[(31, 6, 30)], alpha, beta);
        let mode_mismatch = |err: VerifierError<EF>| {
            matches!(
                err,
                VerifierError::BatchConstraintError(
                    BatchConstraintError::LogUpChallengeModeMismatch
                        | BatchConstraintError::LogUpProofModeMismatch
                )
            )
        };

        // An external-mode key through the internal entry point.
        let err = verify(
            g.engine.config(),
            &g.vk,
            &g.proof,
            &mut g.engine.initial_transcript(),
        );
        assert!(mode_mismatch(err.unwrap_err()));

        // An internal-mode key and proof through the external entry point, and an internal-mode
        // proof that carries a root numerator.
        let internal_engine = Engine::new(riscv_params());
        let airs: Vec<AirRef<Sc>> = vec![
            Arc::new(DummyInteractionAir::new(1, true, LookupType::Byte)),
            Arc::new(DummyInteractionAir::new(1, false, LookupType::Byte)),
        ];
        let (pk, vk) = internal_engine.keygen(&airs);
        let trace = || {
            crate::poly::matrix::ColMajorMatrix::new(
                [1, 1, 1, 1, 5, 6, 7, 8].map(F::from_u32).to_vec(),
                2,
            )
        };
        let ctx: ProvingContext<ReferenceColMajorBackend<Sc>> = ProvingContext::new(
            (0..2)
                .map(|air| (air, AirProvingContext::simple_no_pis(trace())))
                .collect(),
        );
        let internal_proof = internal_engine
            .prover()
            .prove(&internal_engine.device().transport_pk_to_device(&pk), ctx)
            .expect("internal proof");
        internal_engine
            .verify(&vk, &internal_proof)
            .expect("internal proof verifies");
        let err = verify_with_external_logup(
            internal_engine.config(),
            &vk,
            &internal_proof,
            &mut internal_engine.initial_transcript(),
            alpha,
            beta,
        );
        assert!(mode_mismatch(err.unwrap_err()));
        for numerator in [EF::ZERO, EF::ONE] {
            let mut bad = internal_proof.clone();
            bad.gkr_proof.p0_claim = Some(numerator);
            assert!(mode_mismatch(
                internal_engine.verify(&vk, &bad).unwrap_err()
            ));
        }

        // An external-mode key with a proof that lacks the numerator, or carries a proof-of-work
        // witness.
        let mut bad = g.proof.clone();
        bad.gkr_proof.p0_claim = None;
        assert!(mode_mismatch(
            verify_group(&g, &bad, alpha, beta).unwrap_err()
        ));
        let mut bad = g.proof.clone();
        bad.gkr_proof.logup_pow_witness = F::ONE;
        assert!(mode_mismatch(
            verify_group(&g, &bad, alpha, beta).unwrap_err()
        ));
    }

    /// A group proof is bound to its `(alpha, beta)`, its sum and its tables.
    #[test]
    fn forged_group_proofs_are_rejected() {
        let (alpha, beta) = challenges();
        let g = group(&[(41, 6, 30), (42, 6, 64)], alpha, beta);

        // Other challenges than the proof was made under.
        assert!(verify_group(&g, &g.proof, alpha + EF::ONE, beta).is_err());
        assert!(verify_group(&g, &g.proof, alpha, beta + EF::ONE).is_err());

        // A forged sum.
        let mut bad = g.proof.clone();
        *bad.gkr_proof.p0_claim.as_mut().unwrap() += EF::ONE;
        assert!(matches!(
            verify_group(&g, &bad, alpha, beta).unwrap_err(),
            VerifierError::BatchConstraintError(BatchConstraintError::GkrVerificationFailed(
                GkrVerificationError::RootNumeratorCheckFailed { .. }
            ))
        ));
        let mut bad = g.proof.clone();
        bad.gkr_proof.q0_claim += EF::ONE;
        assert!(verify_group(&g, &bad, alpha, beta).is_err());

        // A table left out, and a table swapped for another commitment.
        let mut bad = g.proof.clone();
        bad.trace_vdata[1] = None;
        assert!(matches!(
            verify_group(&g, &bad, alpha, beta).unwrap_err(),
            VerifierError::ProofShapeError(_)
        ));
        let mut bad = g.proof.clone();
        let other = bad.trace_vdata[0].as_ref().unwrap().cached_commitments[0];
        bad.trace_vdata[1].as_mut().unwrap().cached_commitments[0] = other;
        assert!(verify_group(&g, &bad, alpha, beta).is_err());
    }

    /// The encoding of an external-mode proof: the version word carries the mode flag, the
    /// proof-of-work witness is not sent, decoding restores the proof, and the size formula
    /// prices it.
    #[test]
    fn external_mode_proof_encoding() {
        let (alpha, beta) = challenges();
        let g = group(&[(51, 6, 30), (52, 5, 9)], alpha, beta);
        let bytes = g.proof.encode_to_vec().expect("encode");
        let version_word = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(
            version_word,
            crate::proof::CODEC_VERSION | EXTERNAL_LOGUP_PROOF_FLAG
        );
        let decoded = Proof::<Sc>::decode_from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, g.proof);
        assert_eq!(decoded.encode_to_vec().unwrap(), bytes);
        let shape = ProofShape::from_proof(&g.vk.inner, &g.proof).expect("shape");
        assert_eq!(shape.encoded_len::<Sc>(&g.vk.inner.params), bytes.len());

        // The same bytes with the flag cleared claim to be an internal-mode proof: where an
        // external-mode proof has its numerator, they would have a proof-of-work witness, one
        // element for five, and everything after it lands four elements off. They do not
        // decode. (A proof that does decode as an internal-mode one is refused by the group
        // key: `modes_do_not_mix`.)
        let mut cleared = bytes.clone();
        cleared[..4].copy_from_slice(&crate::proof::CODEC_VERSION.to_le_bytes());
        assert!(Proof::<Sc>::decode_from_bytes(&cleared).is_err());
    }

    /// What an external-mode proof absorbs up to the GKR root, in order: the key's pre-hash, the
    /// common main commitment, each table's height and commitment, then `alpha`, `beta`, the
    /// root numerator and the root denominator. Nothing is sampled on the way.
    #[test]
    fn external_mode_absorbs_the_challenges_then_the_root() {
        let (alpha, beta) = challenges();
        let g = group(&[(61, 6, 30), (62, 6, 64)], alpha, beta);
        let mut recorder = crate::config::koala_bear_poseidon2::default_duplex_sponge_recorder();
        let _sum = verify_with_external_logup(
            g.engine.config(),
            &g.vk,
            &g.proof,
            &mut recorder,
            alpha,
            beta,
        )
        .expect("group proof verifies");
        let log = crate::TranscriptHistory::into_log(recorder);

        let mut expected: Vec<F> = Vec::new();
        expected.extend(g.vk.pre_hash);
        expected.extend(g.proof.common_main_commit);
        for vdata in g.proof.trace_vdata.iter().flatten() {
            expected.push(F::from_usize(vdata.log_height));
            expected.extend(vdata.cached_commitments[0]);
        }
        let root = &g.proof.gkr_proof;
        for value in [alpha, beta, root.p0_claim.unwrap(), root.q0_claim] {
            expected.extend_from_slice(value.as_basis_coefficients_slice());
        }
        assert_eq!(&log.values()[..expected.len()], expected.as_slice());
        assert!(log.samples()[..expected.len()]
            .iter()
            .all(|&sampled| !sampled));
    }

    /// An interaction of an external-mode machine may not read the common main trace: the prover
    /// commits it knowing the challenges.
    #[test]
    #[should_panic(expected = "not a cached main column")]
    fn an_external_mode_interaction_cannot_read_the_common_main() {
        // The partitioned dummy AIR takes its count from the common main.
        let engine = Engine::new(group_params(&riscv_params()));
        let mut builder = MultiStarkKeygenBuilder::new(engine.config().clone());
        builder.add_required_air(Arc::new(
            DummyInteractionAir::new(TABLE_WIDTH - 1, true, LookupType::GlobalLogUp).partition(),
        ) as AirRef<Sc>);
        let _ = builder.generate_pk();
    }

    /// [`GlobalLogUpTableAir`] with one thing an external-mode AIR may not have.
    #[derive(Clone, Copy)]
    enum OffTableAir {
        PublicValue,
        NoInteraction,
        /// The multiplicity comes from a preprocessed column instead of the table's.
        PreprocessedCount,
    }

    impl<F: Field> BaseAirWithPublicValues<F> for OffTableAir {
        fn num_public_values(&self) -> usize {
            matches!(self, Self::PublicValue) as usize
        }
    }
    impl<F: Field> PartitionedBaseAir<F> for OffTableAir {
        fn cached_main_widths(&self) -> Vec<usize> {
            vec![TABLE_WIDTH]
        }
        fn common_main_width(&self) -> usize {
            COMMON_MAIN_WIDTH
        }
    }
    impl<F: Field> BaseAir<F> for OffTableAir {
        fn width(&self) -> usize {
            TABLE_WIDTH + COMMON_MAIN_WIDTH
        }
        fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
            matches!(self, Self::PreprocessedCount)
                .then(|| p3_matrix::dense::RowMajorMatrix::new_col(vec![F::ONE; 1 << 6]))
        }
    }
    impl<AB: PartitionedAirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB> for OffTableAir
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            match self {
                Self::PublicValue => GlobalLogUpTableAir.eval(builder),
                Self::NoInteraction => {}
                Self::PreprocessedCount => {
                    let preprocessed = builder.preprocessed().clone();
                    let count = preprocessed.current_slice()[0];
                    let row = builder.cached_mains()[0].current_slice().to_vec();
                    let message = row[..MESSAGE_LEN].iter().map(|&v| v.into()).collect();
                    builder.looking(SymbolicLookup::new(
                        message,
                        count.into(),
                        LookupType::GlobalLogUp,
                        LookupScope::Regional,
                    ));
                }
            }
        }
    }

    /// Keygen of a one-AIR machine in the external mode.
    fn external_keygen(air: AirRef<Sc>, required: bool) {
        let engine = Engine::new(group_params(&riscv_params()));
        let mut builder = MultiStarkKeygenBuilder::new(engine.config().clone());
        if required {
            builder.add_required_air(air);
        } else {
            builder.add_air(air);
        }
        let _ = builder.generate_pk();
    }

    /// An AIR of an external-mode machine is required: a proof that left a table out would
    /// hand back a sum without it.
    #[test]
    #[should_panic(expected = "must be required")]
    fn an_external_mode_air_is_required() {
        external_keygen(Arc::new(GlobalLogUpTableAir), false);
    }

    /// It has no constraints.
    #[test]
    #[should_panic(expected = "must have no constraints")]
    fn an_external_mode_air_has_no_constraints() {
        external_keygen(
            Arc::new(crate::test_utils::dummy_airs::fib_air::air::FibonacciAir),
            true,
        );
    }

    /// It has an interaction.
    #[test]
    #[should_panic(expected = "must have an interaction")]
    fn an_external_mode_air_has_an_interaction() {
        external_keygen(Arc::new(OffTableAir::NoInteraction), true);
    }

    /// It has no public values: the prover fixes them knowing the challenges.
    #[test]
    #[should_panic(expected = "must have no public values")]
    fn an_external_mode_air_has_no_public_values() {
        external_keygen(Arc::new(OffTableAir::PublicValue), true);
    }

    /// Its interaction reads the tables alone: a preprocessed column is refused like the
    /// common main.
    #[test]
    #[should_panic(expected = "not a cached main column")]
    fn an_external_mode_interaction_cannot_read_a_preprocessed_column() {
        external_keygen(Arc::new(OffTableAir::PreprocessedCount), true);
    }

    /// An external-mode machine needs a first WHIR round within the unique-decoding radius.
    #[test]
    #[should_panic(expected = "unique-decoding radius")]
    fn an_external_mode_machine_needs_a_unique_decoding_first_round() {
        let mut params = group_params(&riscv_params());
        params.whir.proximity = WhirProximityStrategy::ListDecoding { m: 9 };
        assert!(!params.first_whir_round_within_unique_decoding());
        let engine = Engine::new(params);
        let _ = group_keygen(engine.config(), 1);
    }

    /// A group key is refused next to a riscv machine at other parameters.
    #[test]
    #[should_panic(expected = "takes the riscv machine's parameters")]
    fn a_group_key_at_other_parameters_is_refused() {
        let engine = Engine::new(group_params(&riscv_params()));
        let vk = group_keygen(engine.config(), 2).get_vk();
        assert_group_vk(&vk.inner, &test_system_params_small(2, 9, 3));
    }

    /// A group key is scored like any other key. The LogUp round is not a group proof's own, so
    /// it does not enter; the rest clears the production budget at the riscv parameters, with a
    /// machine that has no constraints at all.
    #[test]
    fn group_keys_are_admitted_at_production_parameters() {
        let riscv = crate::config::riscv_params_with_128_bits_security(23);
        let engine = Engine::new(group_params(&riscv));
        for tables in [1, MAX_GROUP_LEN] {
            let vk = group_keygen(engine.config(), tables).get_vk();
            assert_group_vk(&vk.inner, &riscv);
            let score = crate::config::soundness::admit_production_vk("group", "reference", &vk)
                .expect("a group key clears the production budget");
            assert!(score.logup_bits.is_infinite());
            assert!(score.total_bits.is_finite());
        }
    }

    /// The first-round radius check is exact at the endpoint `(1 - rho) / 2`.
    #[test]
    fn first_round_radius_check() {
        let with = |log_blowup: usize, proximity| {
            let mut params = riscv_params();
            params.log_blowup = log_blowup;
            params.whir.proximity = proximity;
            params.first_whir_round_within_unique_decoding()
        };
        assert!(with(1, WhirProximityStrategy::UniqueDecoding));
        assert!(with(
            1,
            WhirProximityStrategy::SplitUniqueList {
                m: 9,
                list_start_round: 1
            }
        ));
        assert!(!with(
            1,
            WhirProximityStrategy::SplitUniqueList {
                m: 9,
                list_start_round: 0
            }
        ));
        // Rate 1/4: m = 2 is exactly the unique-decoding radius, m = 3 is past it.
        assert!(with(2, WhirProximityStrategy::ListDecoding { m: 2 }));
        assert!(!with(2, WhirProximityStrategy::ListDecoding { m: 3 }));
        // Rate 1/2: m = 8 is within it, m = 9 is past it.
        assert!(with(1, WhirProximityStrategy::ListDecoding { m: 8 }));
        assert!(!with(1, WhirProximityStrategy::ListDecoding { m: 9 }));
        // The production riscv preset.
        assert!(crate::config::riscv_params_with_128_bits_security(23)
            .first_whir_round_within_unique_decoding());
    }
}
