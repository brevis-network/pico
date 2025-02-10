//! Programs that can be emulated by the Pico zkVM.

use crate::{
    compiler::{program::ProgramBehavior, riscv::instruction::Instruction},
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    machine::{
        lookup::LookupType,
        septic::{SepticCurve, SepticCurveComplete, SepticDigest, SepticExtension},
    },
};
use alloc::sync::Arc;
use p3_field::{FieldExtensionAlgebra, PrimeField32};
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A program that can be emulated by the Pico zkVM.
///
/// Contains a series of instructions along with the initial memory image. It also contains the
/// start address and base address of the program.
///
/// This could be used across different machines
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Program {
    /// The instructions of the program.
    pub instructions: Arc<[Instruction]>,
    /// The start address of the program.
    pub pc_start: u32,
    /// The base address of the program.
    pub pc_base: u32,
    /// The initial memory image, useful for global constants.
    pub memory_image: Arc<BTreeMap<u32, u32>>,
    /// The shape for the preprocessed tables.
    pub preprocessed_shape: Option<RiscvPadShape>,
}

impl Program {
    /// Create a new [Program].
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start: u32, pc_base: u32) -> Self {
        Self {
            instructions: instructions.into(),
            pc_start,
            pc_base,
            memory_image: BTreeMap::new().into(),
            preprocessed_shape: None,
        }
    }

    /// Pad the trace to a power of two according to the proof shape.
    pub fn fixed_log2_rows(&self, chip_name: &String) -> Option<usize> {
        self.preprocessed_shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(chip_name)
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", chip_name))
            })
            .copied()
    }

    pub fn fetch(&self, pc: u32) -> Instruction {
        let idx = (pc - self.pc_base) as usize / 4;
        self.instructions[idx]
    }
}

impl<F: PrimeField32> ProgramBehavior<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }

    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            pc_start: self.pc_start,
            pc_base: self.pc_base,
            memory_image: self.memory_image.clone(),
            preprocessed_shape: self.preprocessed_shape.clone(),
        }
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        let mut digests: Vec<SepticCurveComplete<F>> = self
            .memory_image
            .iter()
            .par_bridge()
            .map(|(&addr, &word)| {
                let values = [
                    (LookupType::Memory as u32) << 16,
                    0,
                    addr,
                    word & 255,
                    (word >> 8) & 255,
                    (word >> 16) & 255,
                    (word >> 24) & 255,
                ];
                let x_start =
                    SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(values[i]));
                let (point, _, _, _) = SepticCurve::<F>::lift_x(x_start);
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();
        digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            digests
                .into_par_iter()
                .reduce(|| SepticCurveComplete::Infinity, |a, b| a + b)
                .point(),
        )
    }
}
