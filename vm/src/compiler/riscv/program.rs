//! Programs that can be emulated by the Pico.

use crate::{
    compiler::{
        addr::encode_proof_addr_to_u32_limbs_48, program::ProgramBehavior,
        riscv::instruction::Instruction,
    },
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
};
use alloc::sync::Arc;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A program that can be emulated by the Pico.
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
    pub pc_start: u64,
    /// The base address of the program.
    pub pc_base: u64,
    /// The initial memory image, useful for global constants.
    pub memory_image: Arc<BTreeMap<u64, u64>>,
    /// The shape for the preprocessed tables.
    pub preprocessed_shape: Option<RiscvPadShape>,
    /// The memory functions' address ranges, read from the ELF's symbol table for profiling only
    /// (`MEMORY_FUNCTIONS`): with cycle tracking on, the emulator counts the instructions run in
    /// each. Not part of the program's identity, and empty for a stripped ELF.
    #[serde(skip)]
    pub profiled_functions: Arc<[ProfiledFunction]>,
}

/// The memory functions whose cycles the emulator reports, by symbol name: the runtime's
/// assembly (`memcpy`, `memset`, and in the static library `memmove`, `memcmp`, `bcmp`,
/// `strlen`) or whatever definition the link kept.
pub const MEMORY_FUNCTIONS: [&str; 6] = ["memcpy", "memset", "memmove", "memcmp", "bcmp", "strlen"];

/// One profiled function: its name and its instructions' addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfiledFunction {
    pub name: &'static str,
    pub range: core::ops::Range<u64>,
}

impl Program {
    /// Create a new [Program].
    #[must_use]
    pub fn new(instructions: Vec<Instruction>, pc_start: u64, pc_base: u64) -> Self {
        Self {
            instructions: instructions.into(),
            pc_start,
            pc_base,
            memory_image: BTreeMap::new().into(),
            preprocessed_shape: None,
            profiled_functions: Arc::new([]),
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

    /// The addresses the code occupies, `[pc_base, pc_base + 4 * instructions)`: the executable
    /// segments, which the loader requires to be contiguous.
    #[must_use]
    pub fn code(&self) -> core::ops::Range<u64> {
        self.pc_base..self.pc_base + 4 * self.instructions.len() as u64
    }

    pub fn fetch(&self, pc: u64) -> Instruction {
        let idx = (pc - self.pc_base) as usize / 4;
        self.instructions[idx]
    }

    /// Whether `pc` is the address of one of the program's instructions: 4-aligned and inside
    /// `[pc_base, pc_base + 4 * len)`.
    #[inline(always)]
    pub fn contains_pc(&self, pc: u64) -> bool {
        // Below `pc_base` the subtraction wraps to a value no program length reaches.
        pc.is_multiple_of(4) && pc.wrapping_sub(self.pc_base) < (self.instructions.len() as u64) * 4
    }

    /// The instruction at `pc`, or `None` where [`Self::contains_pc`] does not hold.
    #[inline(always)]
    pub fn try_fetch(&self, pc: u64) -> Option<Instruction> {
        self.contains_pc(pc).then(|| self.fetch(pc))
    }
}

impl<F: PrimeField32> ProgramBehavior<F> for Program {
    fn pc_start(&self) -> [F; 3] {
        encode_proof_addr_to_u32_limbs_48(self.pc_start, "program start pc").map(F::from_u32)
    }

    fn clone(&self) -> Self {
        Self {
            instructions: self.instructions.clone(),
            pc_start: self.pc_start,
            pc_base: self.pc_base,
            memory_image: self.memory_image.clone(),
            preprocessed_shape: self.preprocessed_shape.clone(),
            profiled_functions: self.profiled_functions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Program;
    use crate::compiler::program::ProgramBehavior;
    use p3_koala_bear::KoalaBear;

    #[test]
    #[should_panic(expected = "frozen 48-bit proof address contract")]
    fn pc_start_rejects_values_above_48_bits() {
        let program = Program {
            pc_start: 1u64 << 48,
            ..Program::default()
        };

        let _ = <Program as ProgramBehavior<KoalaBear>>::pc_start(&program);
    }
}
