use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{BabyBearFriConfigVariable, CircuitConfig},
            fri::{dummy_hash, dummy_pcs_proof, PolynomialBatchShape, PolynomialShape},
            stark::BaseProofVariable,
            types::BaseVerifyingKeyVariable,
            witness::{witnessable::Witnessable, WitnessWriter},
        },
        prelude::*,
    },
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val},
    },
    instances::compiler_v2::shapes::ProofShape,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues},
        septic::SepticDigest,
        utils::order_chips,
    },
    primitives::consts::{DIGEST_SIZE, MAX_NUM_PVS_V2},
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_commit::Pcs;
use p3_field::{ExtensionField, Field, FieldAlgebra};
use p3_matrix::Dimensions;
use std::sync::Arc;

#[derive(Clone)]
pub struct ConvertStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub machine: &'a BaseMachine<SC, C>,
    pub riscv_vk: &'a BaseVerifyingKey<SC>,
    pub proofs: Vec<BaseProof<SC>>,
    pub base_challenger: SC::Challenger,
    pub reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
    pub flag_first_chunk: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
}

pub struct ConvertStdinVariable<CC: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<CC>>
{
    pub riscv_vk: BaseVerifyingKeyVariable<CC, SC>,
    pub proofs: Vec<BaseProofVariable<CC, SC>>,
    pub flag_complete: Felt<CC::F>,
    pub flag_first_chunk: Felt<CC::F>,
    pub vk_root: [Felt<CC::F>; DIGEST_SIZE],
}

impl<'a, SC, C> ConvertStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        machine: &'a BaseMachine<SC, C>,
        riscv_vk: &'a BaseVerifyingKey<SC>,
        proofs: Vec<BaseProof<SC>>,
        base_challenger: SC::Challenger,
        reconstruct_challenger: SC::Challenger,
        flag_complete: bool,
        flag_first_chunk: bool,
        vk_root: [SC::Val; DIGEST_SIZE],
    ) -> Self {
        Self {
            machine,
            riscv_vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
            flag_first_chunk,
            vk_root,
        }
    }
}

impl<CC, C> Witnessable<CC> for ConvertStdin<'_, BabyBearPoseidon2, C>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>,
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type WitnessVariable = ConvertStdinVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let riscv_vk = self.riscv_vk.read(builder);
        let proofs = self.proofs.read(builder);
        let flag_complete = SC_Val::from_bool(self.flag_complete).read(builder);
        let flag_first_chunk = SC_Val::from_bool(self.flag_first_chunk).read(builder);
        let vk_root = self.vk_root.read(builder);

        ConvertStdinVariable {
            riscv_vk,
            proofs,
            flag_complete,
            flag_first_chunk,
            vk_root,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.riscv_vk.write(witness);
        self.proofs.write(witness);
        self.flag_complete.write(witness);
        self.flag_first_chunk.write(witness);
        self.vk_root.write(witness);
    }
}

/// Make a dummy proof for a given proof shape.
pub fn dummy_vk_and_chunk_proof<CB>(
    machine: &BaseMachine<BabyBearPoseidon2, CB>,
    shape: &ProofShape,
) -> (
    BaseVerifyingKey<BabyBearPoseidon2>,
    BaseProof<BabyBearPoseidon2>,
)
where
    CB: ChipBehavior<BabyBear>
        + for<'a> Air<ProverConstraintFolder<'a, BabyBearPoseidon2>>
        + for<'a> Air<VerifierConstraintFolder<'a, BabyBearPoseidon2>>,
{
    // Make a dummy commitment.
    let commitments = BaseCommitments {
        main_commit: dummy_hash(),
        permutation_commit: dummy_hash(),
        quotient_commit: dummy_hash(),
    };

    // Get dummy opened values by reading the chip ordering from the shape.
    let chip_ordering = shape
        .chip_information
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.clone(), i))
        .collect::<HashMap<_, _>>();
    let chips = machine.chips();
    let chunk_chips =
        order_chips::<BabyBearPoseidon2, CB>(&*chips, &chip_ordering).collect::<Vec<_>>();
    let opened_values = BaseOpenedValues {
        chips_opened_values: chunk_chips
            .iter()
            .zip_eq(shape.chip_information.iter())
            .map(|(chip, (_, log_main_degree))| {
                dummy_opened_values::<_, _, _>(chip, *log_main_degree)
            })
            .map(Arc::new)
            .collect(),
    };

    let mut preprocessed_names_and_dimensions = vec![];
    let mut preprocessed_batch_shape = vec![];
    let mut main_batch_shape = vec![];
    let mut permutation_batch_shape = vec![];
    let mut quotient_batch_shape = vec![];
    let mut log_main_degrees = vec![];
    let mut log_quotient_degrees = vec![];

    for (chip, chip_opening) in chunk_chips
        .iter()
        .zip_eq(opened_values.chips_opened_values.iter())
    {
        log_main_degrees.push(chip_opening.log_main_degree);
        // TODO: should we multiple by 4?
        log_quotient_degrees.push(chip_opening.log_main_degree);
        if !chip_opening.preprocessed_local.is_empty() {
            let prep_shape = PolynomialShape {
                width: chip_opening.preprocessed_local.len(),
                log_degree: chip_opening.log_main_degree,
            };
            preprocessed_names_and_dimensions.push((
                chip.name(),
                prep_shape.width,
                prep_shape.log_degree,
            ));
            preprocessed_batch_shape.push(prep_shape);
        }
        let main_shape = PolynomialShape {
            width: chip_opening.main_local.len(),
            log_degree: chip_opening.log_main_degree,
        };
        main_batch_shape.push(main_shape);

        let permutation_shape = PolynomialShape {
            width: chip_opening.permutation_local.len(),
            log_degree: chip_opening.log_main_degree,
        };
        permutation_batch_shape.push(permutation_shape);
        for quot_chunk in chip_opening.quotient.iter() {
            assert_eq!(quot_chunk.len(), 4);
            quotient_batch_shape.push(PolynomialShape {
                width: quot_chunk.len(),
                log_degree: chip_opening.log_main_degree,
            });
        }
    }

    let batch_shapes = vec![
        PolynomialBatchShape {
            shapes: preprocessed_batch_shape,
        },
        PolynomialBatchShape {
            shapes: main_batch_shape,
        },
        PolynomialBatchShape {
            shapes: permutation_batch_shape,
        },
        PolynomialBatchShape {
            shapes: quotient_batch_shape,
        },
    ];

    let fri_queries = machine.config().fri_config().num_queries;
    let log_blowup = machine.config().fri_config().log_blowup;
    let opening_proof = dummy_pcs_proof(fri_queries, &batch_shapes, log_blowup);

    let public_values = (0..MAX_NUM_PVS_V2)
        .map(|_| BabyBear::ZERO)
        .collect::<Vec<_>>();

    // Get the preprocessed chip information.
    let config = machine.config();
    let pcs = config.pcs();
    let preprocessed_chip_information: Vec<_> = preprocessed_names_and_dimensions
        .iter()
        .map(|(name, width, log_height)| {
            let domain = <<BabyBearPoseidon2 as StarkGenericConfig>::Pcs as Pcs<
                <BabyBearPoseidon2 as StarkGenericConfig>::Challenge,
                <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
            >>::natural_domain_for_degree(pcs, 1 << log_height);
            (
                name.to_owned(),
                domain,
                Dimensions {
                    width: *width,
                    height: 1 << log_height,
                },
            )
        })
        .collect();

    // Get the chip ordering.
    let preprocessed_chip_ordering = preprocessed_names_and_dimensions
        .iter()
        .enumerate()
        .map(|(i, (name, _, _))| (name.to_owned(), i))
        .collect::<HashMap<_, _>>();

    let vk = BaseVerifyingKey {
        commit: dummy_hash(),
        pc_start: BabyBear::ZERO,
        initial_global_cumulative_sum: SepticDigest::<BabyBear>::zero(),
        preprocessed_info: preprocessed_chip_information.into(),
        preprocessed_chip_ordering: preprocessed_chip_ordering.into(),
    };

    let chunk_proof = BaseProof {
        commitments,
        opened_values,
        opening_proof,
        log_main_degrees: Arc::from(log_main_degrees),
        log_quotient_degrees: Arc::from(log_quotient_degrees),
        main_chip_ordering: Arc::from(chip_ordering),
        public_values: public_values.into(),
    };

    (vk, chunk_proof)
}

fn dummy_opened_values<F: Field, EF: ExtensionField<F>, CB: ChipBehavior<F>>(
    chip: &MetaChip<F, CB>,
    log_main_degree: usize,
) -> ChipOpenedValues<F, EF> {
    let preprocessed_width = chip.preprocessed_width();
    let preprocessed_local = vec![EF::ZERO; preprocessed_width];
    let preprocessed_next = vec![EF::ZERO; preprocessed_width];

    let main_width = chip.width();
    let main_local = vec![EF::ZERO; main_width];
    let main_next = vec![EF::ZERO; main_width];

    let permutation_width = chip.permutation_width();
    let permutation_local = vec![EF::ZERO; permutation_width * EF::D];
    let permutation_next = vec![EF::ZERO; permutation_width * EF::D];

    let quotient_width = chip.logup_batch_size();
    let quotient = (0..quotient_width)
        .map(|_| vec![EF::ZERO; EF::D])
        .collect::<Vec<_>>();

    ChipOpenedValues {
        preprocessed_local,
        preprocessed_next,
        main_local,
        main_next,
        permutation_local,
        permutation_next,
        quotient,
        global_cumulative_sum: SepticDigest::<F>::zero(),
        regional_cumulative_sum: EF::ZERO,
        log_main_degree,
    }
}
