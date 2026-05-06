//! Programs that can be emulated by the Pico.

use crate::{
    compiler::{
        addr::encode_proof_addr_to_u32_limbs_48, program::ProgramBehavior,
        riscv::instruction::Instruction,
    },
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    iter::{IntoPicoIterator, PicoBridge, PicoIterator},
    machine::{
        lookup::LookupType,
        septic::{SepticCurve, SepticCurveComplete, SepticDigest},
    },
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

    pub fn fetch(&self, pc: u64) -> Instruction {
        let idx = (pc - self.pc_base) as usize / 4;
        self.instructions[idx]
    }
}

impl<F: PrimeField32> ProgramBehavior<F> for Program {
    fn pc_start(&self) -> [F; 3] {
        encode_proof_addr_to_u32_limbs_48(self.pc_start, "program start pc")
            .map(F::from_canonical_u32)
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
            .pico_bridge()
            .map(|(&addr, &word)| {
                // Stage 3 keeps the frozen 48-bit proof-side address encoding here, while the
                // value transport remains full-width RV64 via four u16 limbs.
                let [addr_0, addr_1, addr_2] =
                    encode_proof_addr_to_u32_limbs_48(addr, "program memory address");

                // word: full u64 machine value split into 4×u16 limbs
                let v0 = (word & 0xFFFF) as u32;
                let v1 = ((word >> 16) & 0xFFFF) as u32;
                let v2 = ((word >> 32) & 0xFFFF) as u32;
                let v3 = ((word >> 48) & 0xFFFF) as u32;

                // v2 packing: split v2 into lower byte and upper byte
                let v2_lower = v2 & 0xFF;
                let v2_upper = (v2 >> 8) & 0xFF;

                let values: [F; 8] = [
                    // slot0: kind << 24 (chunk=0 for initialization, clk=0)
                    F::from_canonical_u32((LookupType::Memory as u32) << 24),
                    // slot1: clk = 0
                    F::ZERO,
                    // slot2-4: addr 3×u16
                    F::from_canonical_u32(addr_0),
                    F::from_canonical_u32(addr_1),
                    F::from_canonical_u32(addr_2),
                    // slot5: v0 + v2_lower << 16
                    F::from_canonical_u32(v0 + (v2_lower << 16)),
                    // slot6: v1 + v2_upper << 16
                    F::from_canonical_u32(v1 + (v2_upper << 16)),
                    // slot7: v3
                    F::from_canonical_u32(v3),
                ];
                let (point, _, _, _) = SepticCurve::<F>::lift_x(values);
                SepticCurveComplete::Affine(point.neg())
            })
            .collect();
        digests.push(SepticCurveComplete::Affine(SepticDigest::<F>::zero().0));
        SepticDigest(
            digests
                .into_pico_iter()
                .pico_reduce(|| SepticCurveComplete::Infinity, |a, b| a + b)
                .point(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Program;
    use crate::{compiler::program::ProgramBehavior, machine::septic::SepticDigest};
    use p3_koala_bear::KoalaBear;
    use std::{collections::BTreeMap, sync::Arc};

    #[test]
    fn initial_global_cumulative_sum_uses_upper_32_bits_of_memory_values() {
        let lower_only = Program {
            memory_image: Arc::new(BTreeMap::from([(0x1000, 0x0000_0000_CAFE_BABEu64)])),
            ..Default::default()
        };

        let with_upper_bits = Program {
            memory_image: Arc::new(BTreeMap::from([(0x1000, 0xDEAD_BEEF_CAFE_BABEu64)])),
            ..Default::default()
        };

        let lower_digest: SepticDigest<KoalaBear> = lower_only.initial_global_cumulative_sum();
        let upper_digest: SepticDigest<KoalaBear> = with_upper_bits.initial_global_cumulative_sum();

        assert_ne!(lower_digest, upper_digest);
    }

    #[test]
    fn initial_global_cumulative_sum_accepts_full_u64_memory_values() {
        let program = Program {
            memory_image: Arc::new(BTreeMap::from([(0x1234, 0xFFFF_FFFF_0000_0001u64)])),
            ..Default::default()
        };

        let digest: SepticDigest<KoalaBear> = program.initial_global_cumulative_sum();
        assert!(!digest.is_zero());
    }

    #[test]
    #[should_panic(expected = "frozen 48-bit proof address contract")]
    fn initial_global_cumulative_sum_rejects_addresses_above_48_bits() {
        let program = Program {
            memory_image: Arc::new(BTreeMap::from([((1u64 << 48), 1u64)])),
            ..Default::default()
        };

        let _: SepticDigest<KoalaBear> = program.initial_global_cumulative_sum();
    }

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
