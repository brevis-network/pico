use crate::{
    chips::chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        batch_fri::BatchFRIChip,
        exp_reverse_bits_v2::ExpReverseBitsLenChip,
        poseidon2_wide_v2::Poseidon2WideChip,
        public_values_v2::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        recursion_memory_v2::{constant::MemoryConstChip, variable::MemoryVarChip},
        select::SelectChip,
    },
    compiler::recursion_v2::program::RecursionProgram,
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType, compiler_v2::shapes::ProofShape,
    },
    machine::chip::ChipBehavior,
    primitives::consts::EXTENSION_DEGREE,
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_util::log2_ceil_usize;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tracing::{info, warn};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RiscvRecursionShape {
    pub proof_shapes: Vec<ProofShape>,
    pub is_complete: bool,
}

impl From<ProofShape> for RiscvRecursionShape {
    fn from(proof_shape: ProofShape) -> Self {
        Self {
            proof_shapes: vec![proof_shape],
            is_complete: false,
        }
    }
}

/// The shape of the compress proof with vk validation proofs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursionVkShape {
    pub recursion_shape: RecursionShape,
    pub merkle_tree_height: usize,
}

impl RecursionVkShape {
    pub fn from_proof_shapes(proof_shapes: Vec<ProofShape>, height: usize) -> Self {
        Self {
            recursion_shape: proof_shapes.into(),
            merkle_tree_height: height,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursionShape {
    pub proof_shapes: Vec<ProofShape>,
}

impl From<Vec<ProofShape>> for RecursionShape {
    fn from(proof_shapes: Vec<ProofShape>) -> Self {
        Self { proof_shapes }
    }
}

pub struct RecursionShapeConfig<F, A> {
    allowed_shapes: Vec<HashMap<String, usize>>,
    _marker: PhantomData<(F, A)>,
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize> Default
    for RecursionShapeConfig<F, RecursionChipType<F, DEGREE>>
{
    fn default() -> Self {
        let mem_const =
            RecursionChipType::<F, DEGREE>::MemoryConst(MemoryConstChip::default()).name();
        let mem_var = RecursionChipType::<F, DEGREE>::MemoryVar(MemoryVarChip::default()).name();
        let base_alu = RecursionChipType::<F, DEGREE>::BaseAlu(BaseAluChip::default()).name();
        let ext_alu = RecursionChipType::<F, DEGREE>::ExtAlu(ExtAluChip::default()).name();
        let poseidon2_wide =
            RecursionChipType::<F, DEGREE>::Poseidon2Wide(Poseidon2WideChip::default()).name();
        let exp_reverse_bits_len =
            RecursionChipType::<F, DEGREE>::ExpReverseBitsLen(ExpReverseBitsLenChip::default())
                .name();

        let public_values =
            RecursionChipType::<F, DEGREE>::PublicValues(PublicValuesChip::default()).name();
        let batch_fri =
            RecursionChipType::<F, DEGREE>::BatchFRI(BatchFRIChip::<DEGREE, F>::default()).name();
        let select = RecursionChipType::<F, DEGREE>::Select(SelectChip::default()).name();

        // Specify allowed shapes.
        let allowed_shapes = [
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 16),
                (mem_var.clone(), 19),
                (poseidon2_wide.clone(), 17),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 18),
                (exp_reverse_bits_len.clone(), 18),
                (select.clone(), 19),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 15),
                (mem_var.clone(), 19),
                (poseidon2_wide.clone(), 17),
                (mem_const.clone(), 16),
                (batch_fri.clone(), 20),
                (exp_reverse_bits_len.clone(), 16),
                (select.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 15),
                (mem_var.clone(), 18),
                (poseidon2_wide.clone(), 16),
                (mem_const.clone(), 17),
                (batch_fri.clone(), 19),
                (exp_reverse_bits_len.clone(), 17),
                (select.clone(), 19),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 16),
                (mem_var.clone(), 19),
                (poseidon2_wide.clone(), 17),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 19),
                (exp_reverse_bits_len.clone(), 18),
                (select.clone(), 19),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 17),
                (base_alu.clone(), 16),
                (mem_var.clone(), 20),
                (poseidon2_wide.clone(), 18),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 21),
                (exp_reverse_bits_len.clone(), 18),
                (select.clone(), 20),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // recursion shape for all 22 log_size chips
            // [
            //     (ext_alu.clone(), 16),
            //     (base_alu.clone(), 15),
            //     (mem_var.clone(), 18),
            //     (poseidon2_wide.clone(), 16),
            //     (mem_const.clone(), 16),
            //     (batch_fri.clone(), 19),
            //     (exp_reverse_bits_len.clone(), 18),
            //     (select.clone(), 19),
            //     (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            // ],
        ]
        .map(HashMap::from)
        .to_vec();
        Self {
            allowed_shapes,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>, const DEGREE: usize>
    RecursionShapeConfig<F, RecursionChipType<F, DEGREE>>
{
    pub fn get_all_shape_combinations(
        &self,
        batch_size: usize,
    ) -> impl Iterator<Item = Vec<ProofShape>> + '_ {
        (0..batch_size)
            .map(|_| {
                self.allowed_shapes
                    .iter()
                    .cloned()
                    .map(|map| map.into_iter().collect::<ProofShape>())
            })
            .multi_cartesian_product()
    }

    // Get the allowed shape with a minimal hamming distance from the current shape.
    pub fn padding_shape(&self, program: &mut RecursionProgram<F>) {
        info!("-------------Recursion Padding Shape-------------");
        let heights = RecursionChipType::<F, DEGREE>::chip_heights(program);
        let mut min_distance = usize::MAX;
        let mut closest_shape = None;
        for shape in self.allowed_shapes.iter() {
            let mut distance = 0;
            let mut is_valid = true;
            for (name, height) in heights.iter() {
                let next_power_of_two = height.next_power_of_two();
                let allowed_log_height = shape.get(name).unwrap();
                let allowed_height: usize = 1 << allowed_log_height;
                if next_power_of_two != allowed_height {
                    distance += 1;
                }
                if next_power_of_two > allowed_height {
                    is_valid = false;
                }
            }
            if is_valid && distance < min_distance {
                min_distance = distance;
                closest_shape = Some(shape.clone());
            }
        }

        if let Some(shape) = closest_shape {
            let shape = RecursionPadShape { inner: shape };

            for (chip_name, height) in heights.iter() {
                if shape.inner.contains_key(chip_name) {
                    info!(
                        "Chip {:<20}: {:<3} -> {:<3}",
                        chip_name,
                        log2_ceil_usize(*height),
                        shape.inner[chip_name],
                    );
                } else {
                    warn!(
                        "Unexpected: Chip {} not found in shape, log size: {}",
                        chip_name,
                        log2_ceil_usize(*height)
                    );
                }
            }

            program.shape = Some(shape);
        } else {
            let mut heights_log_sizes = String::new();
            for (chip_name, height) in heights.iter() {
                heights_log_sizes.push_str(&format!(
                    "Chip: {}, Log Size: {}\n",
                    chip_name,
                    log2_ceil_usize(*height)
                ));
            }

            panic!(
                "No shape found for heights. Heights log sizes:\n{}",
                heights_log_sizes
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionPadShape {
    pub(crate) inner: HashMap<String, usize>,
}
