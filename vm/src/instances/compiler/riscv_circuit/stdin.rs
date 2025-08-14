use crate::{
    compiler::recursion::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            fri::{
                dummy_hash, dummy_pcs_proof_bb, dummy_pcs_proof_kb, PolynomialBatchShape,
                PolynomialShape,
            },
            hash::FieldHasher,
            stark::BaseProofVariable,
            types::{BaseVerifyingKeyVariable, FriProofVariable},
            witness::{witnessable::Witnessable, WitnessWriter},
        },
        prelude::*,
    },
    configs::{
        config::{Challenger, Com, PcsProof, StarkGenericConfig},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            shapes::{recursion_shape::RecursionVkShape, ProofShape},
            vk_merkle::stdin::{MerkleProofStdin, MerkleProofStdinVariable, RecursionVkStdin},
        },
        machine::{combine::CombineMachine, deferred::DeferredMachine},
    },
    machine::{
        chip::{ChipBehavior, MetaChip},
        keys::BaseVerifyingKey,
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues},
        septic::SepticDigest,
        utils::order_chips,
    },
    primitives::consts::{DIGEST_SIZE, MAX_NUM_PVS, RECURSION_NUM_PVS},
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::{ExtensionField, Field, FieldAlgebra, TwoAdicField};
use p3_koala_bear::KoalaBear;
use p3_matrix::Dimensions;
use std::sync::Arc;

#[derive(Clone)]
pub struct ConvertStdin<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    pub machine: BaseMachine<SC, C>,
    pub riscv_vk: BaseVerifyingKey<SC>,
    pub proofs: Arc<[BaseProof<SC>]>,
    pub base_challenger: SC::Challenger,
    pub reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
    pub flag_first_chunk: bool,
    pub vk_root: [SC::Val; DIGEST_SIZE],
    pub deferred_digest: [SC::Val; DIGEST_SIZE],
}

#[derive(Clone)]
pub struct DeferredStdin<SC, C>
where
    SC: StarkGenericConfig + FieldHasher<SC::Val>,
    C: ChipBehavior<SC::Val>,
{
    pub machine: BaseMachine<SC, C>,
    pub proof: BaseProof<SC>,
    pub recursion_vk: BaseVerifyingKey<SC>,
    pub recursion_vk_merkle_data: MerkleProofStdin<SC>,
    pub start_reconstruct_deferred_digest: [SC::Val; DIGEST_SIZE],
    pub riscv_vk_digest: [SC::Val; DIGEST_SIZE],
    pub end_pc: SC::Val,
}

pub struct DeferredStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub proof: BaseProofVariable<CC, SC>,
    pub recursion_vk: BaseVerifyingKeyVariable<CC, SC>,
    pub recursion_vk_merkle_data: MerkleProofStdinVariable<CC, SC>,
    pub start_reconstruct_deferred_digest: [Felt<CC::F>; DIGEST_SIZE],
    pub riscv_vk_digest: [Felt<CC::F>; DIGEST_SIZE],
    pub end_pc: Felt<CC::F>,
}

pub struct ConvertStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub riscv_vk: BaseVerifyingKeyVariable<CC, SC>,
    pub proofs: Vec<BaseProofVariable<CC, SC>>,
    pub flag_complete: Felt<CC::F>,
    pub flag_first_chunk: Felt<CC::F>,
    pub vk_root: [Felt<CC::F>; DIGEST_SIZE],
    pub deferred_digest: [Felt<CC::F>; DIGEST_SIZE],
}

impl<F, SC, C> ConvertStdin<SC, C>
where
    F: Field,
    SC: StarkGenericConfig<Val = F>,
    C: ChipBehavior<F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        machine: &BaseMachine<SC, C>,
        riscv_vk: &BaseVerifyingKey<SC>,
        proofs: Vec<BaseProof<SC>>,
        base_challenger: SC::Challenger,
        reconstruct_challenger: SC::Challenger,
        flag_complete: bool,
        flag_first_chunk: bool,
        vk_root: [SC::Val; DIGEST_SIZE],
        deferred_digest: [SC::Val; DIGEST_SIZE],
    ) -> Self {
        Self {
            machine: machine.clone(),
            riscv_vk: riscv_vk.clone(),
            proofs: proofs.into(),
            base_challenger,
            reconstruct_challenger,
            flag_complete,
            flag_first_chunk,
            vk_root,
            deferred_digest,
        }
    }
}

impl<CC, SC, C> Witnessable<CC> for ConvertStdin<SC, C>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
    C: ChipBehavior<CC::F>,
{
    type WitnessVariable = ConvertStdinVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let riscv_vk = self.riscv_vk.read(builder);
        let proofs = self.proofs.as_ref().read(builder);
        let flag_complete = CC::F::from_bool(self.flag_complete).read(builder);
        let flag_first_chunk = CC::F::from_bool(self.flag_first_chunk).read(builder);
        let vk_root = self.vk_root.read(builder);
        let deferred_digest = self.deferred_digest.read(builder);

        ConvertStdinVariable {
            riscv_vk,
            proofs,
            flag_complete,
            flag_first_chunk,
            vk_root,
            deferred_digest,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.riscv_vk.write(witness);
        self.proofs.as_ref().write(witness);
        self.flag_complete.write(witness);
        self.flag_first_chunk.write(witness);
        self.vk_root.write(witness);
        self.deferred_digest.write(witness);
    }
}

impl<CC, SC, C> Witnessable<CC> for DeferredStdin<SC, C>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
            CC,
            Val = CC::F,
            Challenge = CC::EF,
            Domain = TwoAdicMultiplicativeCoset<CC::F>,
        > + FieldHasher<CC::F>,
    SC::Digest: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
    C: ChipBehavior<CC::F>,
{
    type WitnessVariable = DeferredStdinVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let proof = self.proof.read(builder);
        let recursion_vk = self.recursion_vk.read(builder);
        let recursion_vk_merkle_data = self.recursion_vk_merkle_data.read(builder);
        let start_reconstruct_deferred_digest =
            self.start_reconstruct_deferred_digest.read(builder);
        let riscv_vk_digest = self.riscv_vk_digest.read(builder);
        let end_pc = self.end_pc.read(builder);

        DeferredStdinVariable {
            proof,
            recursion_vk,
            recursion_vk_merkle_data,
            start_reconstruct_deferred_digest,
            riscv_vk_digest,
            end_pc,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.proof.write(witness);
        self.recursion_vk.write(witness);
        self.recursion_vk_merkle_data.write(witness);
        self.start_reconstruct_deferred_digest.write(witness);
        self.riscv_vk_digest.write(witness);
        self.end_pc.write(witness);
    }
}

/// Make a dummy proof for a given proof shape.
macro_rules! dummy_vk_and_chunk_proof {
    ($func_name:ident, $poseidon_type:ty, $field:ty, $dummy_pcs:ident) => {
        pub fn $func_name<CB>(
            machine: &BaseMachine<$poseidon_type, CB>,
            shape: &ProofShape,
        ) -> (BaseVerifyingKey<$poseidon_type>, BaseProof<$poseidon_type>)
        where
            CB: ChipBehavior<$field>,
        {
            // Make a dummy commitment.
            let commitments = BaseCommitments {
                main_commit: dummy_hash::<$field>(),
                permutation_commit: dummy_hash::<$field>(),
                quotient_commit: dummy_hash::<$field>(),
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
                order_chips::<$poseidon_type, CB>(&chips, &chip_ordering).collect::<Vec<_>>();
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
            let len = chunk_chips.len();
            let mut log_main_degrees = Arc::new_uninit_slice(len);
            let mut log_quotient_degrees = Arc::new_uninit_slice(len);
            let main_writer = Arc::get_mut(&mut log_main_degrees).unwrap();
            let quotient_writer = Arc::get_mut(&mut log_quotient_degrees).unwrap();

            for (i, (chip, chip_opening)) in chunk_chips
                .iter()
                .zip_eq(opened_values.chips_opened_values.iter())
                .enumerate()
            {
                main_writer[i].write(chip_opening.log_main_degree);
                quotient_writer[i].write(chip_opening.log_main_degree);

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

            // SAFETY: we've written chunk_chips.len() elems to the Arc slices
            let log_main_degrees = unsafe { log_main_degrees.assume_init() };
            let log_quotient_degrees = unsafe { log_quotient_degrees.assume_init() };

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
            let opening_proof = $dummy_pcs(fri_queries, &batch_shapes, log_blowup);

            let public_values = (0..MAX_NUM_PVS).map(|_| <$field>::ZERO).collect();

            // Get the preprocessed chip information.
            let config = machine.config();
            let pcs = config.pcs();
            let preprocessed_chip_information: Vec<_> = preprocessed_names_and_dimensions
                .iter()
                .map(|(name, width, log_height)| {
                    let domain = <<$poseidon_type as StarkGenericConfig>::Pcs as Pcs<
                        <$poseidon_type as StarkGenericConfig>::Challenge,
                        <$poseidon_type as StarkGenericConfig>::Challenger,
                    >>::natural_domain_for_degree(&pcs, 1 << log_height);
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
                commit: dummy_hash::<$field>(),
                pc_start: <$field>::ZERO,
                initial_global_cumulative_sum: SepticDigest::<$field>::zero(),
                preprocessed_info: preprocessed_chip_information.into(),
                preprocessed_chip_ordering: preprocessed_chip_ordering.into(),
            };

            let chunk_proof = BaseProof {
                commitments,
                opened_values,
                opening_proof,
                log_main_degrees,
                log_quotient_degrees,
                main_chip_ordering: Arc::new(chip_ordering),
                public_values,
            };

            (vk, chunk_proof)
        }
    };
}

dummy_vk_and_chunk_proof!(
    dummy_vk_and_chunk_proof_kb,
    KoalaBearPoseidon2,
    KoalaBear,
    dummy_pcs_proof_kb
);

dummy_vk_and_chunk_proof!(
    dummy_vk_and_chunk_proof,
    BabyBearPoseidon2,
    BabyBear,
    dummy_pcs_proof_bb
);

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

impl DeferredStdin<KoalaBearPoseidon2, RecursionChipType<KoalaBear>> {
    pub fn dummy(shape: &RecursionVkShape) -> Self {
        let deferred_machine = DeferredMachine::new(
            KoalaBearPoseidon2::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        let combine_machine = CombineMachine::new(
            <KoalaBearPoseidon2>::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        let recursion_vk_stdin =
            RecursionVkStdin::<KoalaBearPoseidon2, RecursionChipType<KoalaBear>>::dummy(
                combine_machine.base_machine(),
                shape,
            );

        assert_eq!(recursion_vk_stdin.recursion_stdin.proofs.len(), 1);
        assert_eq!(recursion_vk_stdin.recursion_stdin.vks.len(), 1);
        Self {
            machine: deferred_machine.base_machine().clone(),
            proof: recursion_vk_stdin.recursion_stdin.proofs[0].clone(),
            recursion_vk: recursion_vk_stdin.recursion_stdin.vks[0].clone(),
            recursion_vk_merkle_data: recursion_vk_stdin.merkle_proof_stdin,
            start_reconstruct_deferred_digest: [KoalaBear::ZERO; DIGEST_SIZE],
            riscv_vk_digest: [KoalaBear::ZERO; DIGEST_SIZE],
            end_pc: KoalaBear::ZERO,
        }
    }
}

impl DeferredStdin<BabyBearPoseidon2, RecursionChipType<BabyBear>> {
    pub fn dummy(shape: &RecursionVkShape) -> Self {
        let deferred_machine = DeferredMachine::new(
            BabyBearPoseidon2::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        let combine_machine = CombineMachine::new(
            <BabyBearPoseidon2>::new(),
            RecursionChipType::combine_chips(),
            RECURSION_NUM_PVS,
        );
        let recursion_vk_stdin =
            RecursionVkStdin::<BabyBearPoseidon2, RecursionChipType<BabyBear>>::dummy(
                combine_machine.base_machine(),
                shape,
            );

        assert_eq!(recursion_vk_stdin.recursion_stdin.proofs.len(), 1);
        assert_eq!(recursion_vk_stdin.recursion_stdin.vks.len(), 1);
        Self {
            machine: deferred_machine.base_machine().clone(),
            proof: recursion_vk_stdin.recursion_stdin.proofs[0].clone(),
            recursion_vk: recursion_vk_stdin.recursion_stdin.vks[0].clone(),
            recursion_vk_merkle_data: recursion_vk_stdin.merkle_proof_stdin,
            start_reconstruct_deferred_digest: [BabyBear::ZERO; DIGEST_SIZE],
            riscv_vk_digest: [BabyBear::ZERO; DIGEST_SIZE],
            end_pc: BabyBear::ZERO,
        }
    }
}
