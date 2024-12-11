//! Programs that can be emulated by the Pico zkVM.

use crate::compiler::{program::ProgramBehavior, riscv::instruction::Instruction};
use alloc::sync::Arc;
use p3_field::Field;
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
        }
    }
}

impl<F: Field> ProgramBehavior<F> for Program {
    fn pc_start(&self) -> F {
        F::from_canonical_u32(self.pc_start)
    }

    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            pc_start: self.pc_start,
            pc_base: self.pc_base,
            memory_image: self.memory_image.clone(),
        }
    }
}
