use super::super::utils::make_selector_col_map;
use crate::compiler::riscv::{instruction::Instruction, opcode::Opcode};
use p3_field::Field;
use pico_derive::AlignedBorrow;
use std::{mem::size_of, vec::IntoIter};

pub const NUM_OPCODE_SELECTOR_COLS: usize = size_of::<OpcodeSelectorCols<u8>>();
pub const OPCODE_SELECTORS_COL_MAP: OpcodeSelectorCols<usize> = make_selector_col_map();

/// The column layout for opcode selectors.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    /// Whether op_b is an immediate value.
    pub imm_b: T,

    /// Whether op_c is an immediate value.
    pub imm_c: T,

    /// Table selectors for opcodes.
    ///
    /// The former `is_alu` column is derived, not committed. Since the instruction
    /// class is a one-hot partition backed by the Program-table lookup (which pins every other
    /// class selector for the row's pc), ALU is exactly the complement:
    /// `is_alu = is_real - (is_ecall + is_memory + Σbranch + is_jal + is_jalr)`.
    /// There is no selector for the trap instructions (UNIMP / EBREAK): the Program table holds
    /// no row for a trap's pc (`riscv_program/traces.rs`), so no Cpu row can carry one. See
    /// `CpuChip::is_alu_instruction`.
    ///
    /// There is no `is_auipc` term since X12: the transpiler re-encodes `AUIPC rd, imm` as the
    /// two-immediate `ADD rd, imm, pc`, so AUIPC is no longer an instruction class this table
    /// knows about. Should an AUIPC instruction still reach this table (a hand-built `Program`),
    /// `populate` sets no class selector and the row falls into the derived ALU class. That is
    /// fail-closed. On an honest trace with `rd != x0` the first thing to fail is the
    /// definitional constraint `is_alu_not_x0 == is_alu_instruction * (1 - op_a_0)`: the AIR
    /// reads `is_alu_instruction = 1` while `riscv_cpu/traces.rs` writes `is_alu_not_x0 = 0`,
    /// because `Instruction::is_alu_instruction` does not list AUIPC. Only a prover that forges
    /// `is_alu_not_x0 = 1` to satisfy it reaches the Alu bus, where nothing receives opcode 27
    /// and the regional sum stops balancing. `auipc x0, imm` passes both checks, correctly: it is
    /// a genuine no-op, with `op_a_val()` pinned to zero and the pc advancing by 4.
    pub is_ecall: T,

    /// Memory Instructions.
    ///
    /// The per-variant flags (is_lb, ..., is_sd) live in the MemoryReadWriteChip's
    /// `MemoryInstructionCols` and are self-proven there against the opcode; the Cpu
    /// chip only tracks whether the instruction is a memory instruction at all, plus
    /// whether it is a store (the register write constraint needs to know that stores,
    /// like branches, must not modify op_a).
    pub is_memory: T,
    pub is_store: T,

    /// Branch Instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_blt: T,
    pub is_bge: T,
    pub is_bltu: T,
    pub is_bgeu: T,

    /// Jump Instructions.
    pub is_jalr: T,
    pub is_jal: T,
}

impl<F: Field> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        // `is_alu` is no longer a committed column; the ALU class is derived in the
        // constraints as the one-hot complement of the other class selectors. On ALU rows this
        // branch simply leaves every class selector at zero.
        if instruction.is_alu_instruction() {
            // no-op: ALU class is derived, not committed.
        } else if instruction.is_ecall_instruction() {
            self.is_ecall = F::ONE;
        } else if instruction.is_memory_instruction() {
            self.is_memory = F::ONE;
            if matches!(
                instruction.opcode,
                Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD
            ) {
                self.is_store = F::ONE;
            }
        } else if instruction.is_branch_instruction() {
            match instruction.opcode {
                Opcode::BEQ => self.is_beq = F::ONE,
                Opcode::BNE => self.is_bne = F::ONE,
                Opcode::BLT => self.is_blt = F::ONE,
                Opcode::BGE => self.is_bge = F::ONE,
                Opcode::BLTU => self.is_bltu = F::ONE,
                Opcode::BGEU => self.is_bgeu = F::ONE,
                _ => unreachable!(),
            }
        } else if instruction.opcode == Opcode::JAL {
            self.is_jal = F::ONE;
        } else if instruction.opcode == Opcode::JALR {
            self.is_jalr = F::ONE;
        }
        // A trap instruction (`Opcode::is_trap`) sets no class selector. It never reaches this
        // point from a real program: the emulator stops on it before emitting an event, and the
        // Program table writes row 0 in its place (`riscv_program/traces.rs`).
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![
            self.imm_b,
            self.imm_c,
            self.is_ecall,
            self.is_memory,
            self.is_store,
            self.is_beq,
            self.is_bne,
            self.is_blt,
            self.is_bge,
            self.is_bltu,
            self.is_bgeu,
            self.is_jalr,
            self.is_jal,
        ];
        assert_eq!(columns.len(), NUM_OPCODE_SELECTOR_COLS);
        columns.into_iter()
    }
}
