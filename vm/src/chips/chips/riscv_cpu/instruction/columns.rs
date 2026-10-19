use crate::compiler::riscv::instruction::Instruction;
use p3_field::Field;
use pico_derive::AlignedBorrow;
use std::{array, iter::once, mem::size_of, vec::IntoIter};

pub const NUM_INSTRUCTION_COLS: usize = size_of::<InstructionCols<u8>>();

// RISC-V X0 register
const REGISTER_X0: u8 = 0;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct InstructionCols<T> {
    /// The opcode for this cycle.
    pub opcode: T,

    /// The first operand for this instruction.  This is a 5-bit register index, so a
    /// single limb suffices (it was previously stored as a full `Word`).
    pub op_a: T,

    /// The second operand for this instruction: a register index or a sign-extended immediate.
    pub op_b: SignExtImm<T>,

    /// The third operand for this instruction: a register index or a sign-extended immediate.
    pub op_c: SignExtImm<T>,

    /// Flags to indicate if op_a is register 0.
    pub op_a_0: T,
}

/// A 64-bit instruction operand whose upper 32 bits are a sign fill: the low two u16 limbs plus
/// one sign bit (a four-limb `Word` would carry the fill twice).
///
/// Every operand the transpiler writes is either a register index, a shift amount, a pc, or an
/// immediate sign-extended from at most 32 bits (`compiler/riscv/disassembler/rrs.rs`), so its
/// bits 32..64 are all zero or all one. Limbs 2 and 3 of the operand word are therefore
/// `0xFFFF * sign` each, and `register/constraints.rs` pins the immediate-row operand value to
/// exactly that. [`InstructionCols::populate`] panics on a value that breaks the invariant, so
/// a program that cannot be represented fails at preprocessed-trace generation rather than
/// proving with a wrong immediate.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct SignExtImm<T> {
    /// Bits 0..16 and 16..32 of the operand.
    pub limb: [T; 2],
    /// Bit 63 of the operand: 1 when bits 32..64 are all one, 0 when they are all zero.
    pub sign: T,
}

impl<F: Field> SignExtImm<F> {
    /// Splits a 64-bit operand into its two low limbs and its sign fill.
    ///
    /// # Panics
    ///
    /// When bits 32..64 of `value` are neither all zero nor all one, i.e. the operand is not a
    /// sign-extended i32 and not a small operand (register index, shift amount, pc).
    pub fn from_u64(value: u64) -> Self {
        let hi = value >> 32;
        assert!(
            hi == 0 || hi == 0xFFFF_FFFF,
            "instruction operand {value:#x} is not a sign-extended i32 or a small operand"
        );
        SignExtImm {
            limb: [
                F::from_u16((value & 0xFFFF) as u16),
                F::from_u16(((value >> 16) & 0xFFFF) as u16),
            ],
            sign: F::from_bool(hi != 0),
        }
    }
}

impl<T> IntoIterator for SignExtImm<T> {
    type Item = T;
    type IntoIter = array::IntoIter<T, 3>;

    /// `limb[0], limb[1], sign` -- the order the Program-table message uses on both ends.
    fn into_iter(self) -> Self::IntoIter {
        let [limb0, limb1] = self.limb;
        [limb0, limb1, self.sign].into_iter()
    }
}

impl<F: Field> InstructionCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.opcode = instruction.opcode.as_field::<F>();

        self.op_a = F::from_u8(instruction.op_a);
        self.op_b = SignExtImm::from_u64(instruction.op_b);
        self.op_c = SignExtImm::from_u64(instruction.op_c);

        self.op_a_0 = F::from_bool(instruction.op_a == REGISTER_X0);
    }
}

impl<T> IntoIterator for InstructionCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        once(self.opcode)
            .chain(once(self.op_a))
            .chain(self.op_b)
            .chain(self.op_c)
            .chain(once(self.op_a_0))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{InstructionCols, SignExtImm};
    use crate::compiler::riscv::{instruction::Instruction, opcode::Opcode};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    #[test]
    fn sign_ext_imm_splits_a_negative_immediate() {
        let imm = SignExtImm::<KoalaBear>::from_u64((-0x1234i64) as u64);
        assert_eq!(
            imm.limb,
            [KoalaBear::from_u16(0xEDCC), KoalaBear::from_u16(0xFFFF)]
        );
        assert_eq!(imm.sign, KoalaBear::ONE);
    }

    #[test]
    fn sign_ext_imm_splits_a_small_operand() {
        let imm = SignExtImm::<KoalaBear>::from_u64(0x7FFF_FFFC);
        assert_eq!(
            imm.limb,
            [KoalaBear::from_u16(0xFFFC), KoalaBear::from_u16(0x7FFF)]
        );
        assert_eq!(imm.sign, KoalaBear::ZERO);
    }

    #[test]
    #[should_panic(expected = "is not a sign-extended i32 or a small operand")]
    fn populate_rejects_an_operand_with_a_partial_sign_fill() {
        let mut cols = InstructionCols::<KoalaBear>::default();
        cols.populate(Instruction::new(
            Opcode::ADD,
            1,
            0x1_0000_0000,
            0,
            true,
            false,
        ));
    }
}
