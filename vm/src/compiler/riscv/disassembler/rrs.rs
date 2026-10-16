use crate::compiler::riscv::{instruction::Instruction, opcode::Opcode, register::Register};
use alloc::sync::Arc;
use rrs_lib::{
    instruction_formats::{
        BType, IType, ITypeCSR, ITypeShamt, ITypeShamtW, JType, RType, SType, UType,
    },
    process_instruction, InstructionProcessor,
};

impl Instruction {
    /// Create a new [`Instruction`] from an R-type instruction.
    #[must_use]
    pub const fn from_r_type(opcode: Opcode, dec_insn: &RType) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as u8,
            dec_insn.rs1,
            dec_insn.rs2,
            false,
            false,
        )
    }

    /// Create a new [`Instruction`] from an I-type instruction.
    #[must_use]
    pub const fn from_i_type(opcode: Opcode, dec_insn: &IType) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as u8,
            dec_insn.rs1,
            dec_insn.imm as u64,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] from an I-type instruction with a shamt.
    #[must_use]
    pub const fn from_i_type_shamt(opcode: Opcode, dec_insn: &ITypeShamt) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as u8,
            dec_insn.rs1,
            dec_insn.shamt,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] from an I-type word instruction with a shamt.
    #[must_use]
    pub const fn from_i_type_shamt_w(opcode: Opcode, dec_insn: &ITypeShamtW) -> Self {
        Self::new(
            opcode,
            dec_insn.rd as u8,
            dec_insn.rs1,
            dec_insn.shamt,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] from an S-type instruction.
    #[must_use]
    pub const fn from_s_type(opcode: Opcode, dec_insn: &SType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs2 as u8,
            dec_insn.rs1,
            dec_insn.imm as u64,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] from a B-type instruction.
    #[must_use]
    pub const fn from_b_type(opcode: Opcode, dec_insn: &BType) -> Self {
        Self::new(
            opcode,
            dec_insn.rs1 as u8,
            dec_insn.rs2,
            dec_insn.imm as u64,
            false,
            true,
        )
    }

    /// Create a new [`Instruction`] that is not implemented.
    #[must_use]
    pub const fn unimp() -> Self {
        Self::new(Opcode::UNIMP, 0, 0, 0, true, true)
    }

    /// Returns if the [`Instruction`] is an R-type instruction.
    #[inline]
    #[must_use]
    pub const fn is_r_type(&self) -> bool {
        !self.imm_c
    }

    /// Returns whether the [`Instruction`] is an I-type instruction.
    #[inline]
    #[must_use]
    pub const fn is_i_type(&self) -> bool {
        self.imm_c
    }

    /// Decode the [`Instruction`] in the R-type format.
    #[inline]
    #[must_use]
    pub fn r_type(&self) -> (Register, Register, Register) {
        (
            Register::from_u8(self.op_a),
            Register::from_u8(self.op_b as u8),
            Register::from_u8(self.op_c as u8),
        )
    }

    /// Decode the [`Instruction`] in the I-type format.
    #[inline]
    #[must_use]
    pub fn i_type(&self) -> (Register, Register, u64) {
        (
            Register::from_u8(self.op_a),
            Register::from_u8(self.op_b as u8),
            self.op_c,
        )
    }

    /// Decode the [`Instruction`] in the S-type format.
    #[inline]
    #[must_use]
    pub fn s_type(&self) -> (Register, Register, u64) {
        (
            Register::from_u8(self.op_a),
            Register::from_u8(self.op_b as u8),
            self.op_c,
        )
    }

    /// Decode the [`Instruction`] in the B-type format.
    #[inline]
    #[must_use]
    pub fn b_type(&self) -> (Register, Register, u64) {
        (
            Register::from_u8(self.op_a),
            Register::from_u8(self.op_b as u8),
            self.op_c,
        )
    }

    /// Decode the [`Instruction`] in the J-type format.
    #[inline]
    #[must_use]
    pub fn j_type(&self) -> (Register, u64) {
        (Register::from_u8(self.op_a), self.op_b)
    }

    /// Decode the [`Instruction`] in the U-type format.
    #[inline]
    #[must_use]
    pub fn u_type(&self) -> (Register, u64) {
        (Register::from_u8(self.op_a), self.op_b)
    }
}

/// A transpiler that converts the 32-bit encoded instructions into instructions.
pub(crate) struct InstructionTranspiler {
    /// Address of the instruction currently being transpiled (`pc_base + 4 * index`).
    ///
    /// `InstructionProcessor` hands the decoder no index, so `transpile` writes this before every
    /// `process_instruction` call. Only `process_auipc` reads it: AUIPC folds its own address into
    /// the encoded instruction, which is what lets it become a plain two-immediate ADD.
    pc: u64,
}

impl InstructionProcessor for InstructionTranspiler {
    type InstructionResult = Instruction;

    fn process_add(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::ADD, &dec_insn)
    }

    fn process_addi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::ADD, &dec_insn)
    }

    fn process_sub(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SUB, &dec_insn)
    }

    fn process_xor(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::XOR, &dec_insn)
    }

    fn process_xori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::XOR, &dec_insn)
    }

    fn process_or(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::OR, &dec_insn)
    }

    fn process_ori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::OR, &dec_insn)
    }

    fn process_and(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::AND, &dec_insn)
    }

    fn process_andi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::AND, &dec_insn)
    }

    fn process_sll(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLL, &dec_insn)
    }

    fn process_slli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(Opcode::SLL, &dec_insn)
    }

    fn process_srl(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SRL, &dec_insn)
    }

    fn process_srli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(Opcode::SRL, &dec_insn)
    }

    fn process_sra(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SRA, &dec_insn)
    }

    fn process_srai(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        Instruction::from_i_type_shamt(Opcode::SRA, &dec_insn)
    }

    fn process_slt(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLT, &dec_insn)
    }

    fn process_slti(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::SLT, &dec_insn)
    }

    fn process_sltu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLTU, &dec_insn)
    }

    fn process_sltui(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::SLTU, &dec_insn)
    }

    fn process_lb(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LB, &dec_insn)
    }

    fn process_lh(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LH, &dec_insn)
    }

    fn process_lw(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LW, &dec_insn)
    }

    fn process_lbu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LBU, &dec_insn)
    }

    fn process_lhu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LHU, &dec_insn)
    }

    fn process_sb(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SB, &dec_insn)
    }

    fn process_sh(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SH, &dec_insn)
    }

    fn process_sw(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SW, &dec_insn)
    }

    fn process_beq(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BEQ, &dec_insn)
    }

    fn process_bne(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BNE, &dec_insn)
    }

    fn process_blt(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BLT, &dec_insn)
    }

    fn process_bge(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BGE, &dec_insn)
    }

    fn process_bltu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BLTU, &dec_insn)
    }

    fn process_bgeu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        Instruction::from_b_type(Opcode::BGEU, &dec_insn)
    }

    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::JAL,
            dec_insn.rd as u8,
            dec_insn.imm as u64,
            0,
            true,
            true,
        )
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::JALR,
            dec_insn.rd as u8,
            dec_insn.rs1,
            dec_insn.imm as u64,
            false,
            true,
        )
    }

    fn process_lui(&mut self, dec_insn: UType) -> Self::InstructionResult {
        // LUI is encoded as ADD rd, 0, imm (with imm_b and imm_c set). The rrs-pico UType `imm`
        // field already contains the upper-20-bit value shifted into position (lower 12 bits
        // zero), so the ADD computes 0 + imm = imm and writes it to rd.
        Instruction::new(Opcode::ADD, dec_insn.rd as u8, 0, dec_insn.imm, true, true)
    }

    /// AUIPC is `rd = pc + (imm << 12)`, and `pc` is a compile-time constant for this slot, so the
    /// instruction is a two-immediate ADD -- the same shape as `process_lui` above, which already
    /// encodes LUI as `ADD rd, 0, imm`. The rrs-pico UType `imm` field already carries the
    /// upper-20-bit value shifted into position and sign-extended to 64 bits, so `imm + pc` is
    /// bit-for-bit the `pc.wrapping_add(imm)` the old AUIPC emulator arm computed.
    ///
    /// Since X12 the transpiler emits no `Opcode::AUIPC` at all: the Cpu AIR has no `is_auipc`
    /// selector, no `is_auipc_not_x0` multiplicity and no AUIPC-specific ALU dispatch.
    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {
        Instruction::new(
            Opcode::ADD,
            dec_insn.rd as u8,
            dec_insn.imm,
            self.pc,
            true,
            true,
        )
    }

    fn process_ecall(&mut self) -> Self::InstructionResult {
        Instruction::new(
            Opcode::ECALL,
            Register::X5 as u8,
            Register::X10 as u64,
            Register::X11 as u64,
            false,
            false,
        )
    }

    fn process_ebreak(&mut self) -> Self::InstructionResult {
        Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false)
    }

    fn process_mul(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MUL, &dec_insn)
    }

    fn process_mulh(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULH, &dec_insn)
    }

    fn process_mulhu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULHU, &dec_insn)
    }

    fn process_mulhsu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULHSU, &dec_insn)
    }

    fn process_div(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::DIV, &dec_insn)
    }

    fn process_divu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::DIVU, &dec_insn)
    }

    fn process_rem(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::REM, &dec_insn)
    }

    fn process_remu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::REMU, &dec_insn)
    }

    // RV64I
    fn process_addw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::ADDW, &dec_insn)
    }

    fn process_subw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SUBW, &dec_insn)
    }

    fn process_sllw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SLLW, &dec_insn)
    }

    fn process_srlw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SRLW, &dec_insn)
    }

    fn process_sraw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::SRAW, &dec_insn)
    }

    fn process_addiw(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::ADDW, &dec_insn)
    }

    fn process_slliw(&mut self, dec_insn: ITypeShamtW) -> Self::InstructionResult {
        Instruction::from_i_type_shamt_w(Opcode::SLLW, &dec_insn)
    }

    fn process_srliw(&mut self, dec_insn: ITypeShamtW) -> Self::InstructionResult {
        Instruction::from_i_type_shamt_w(Opcode::SRLW, &dec_insn)
    }

    fn process_sraiw(&mut self, dec_insn: ITypeShamtW) -> Self::InstructionResult {
        Instruction::from_i_type_shamt_w(Opcode::SRAW, &dec_insn)
    }

    fn process_lwu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LWU, &dec_insn)
    }

    fn process_ld(&mut self, dec_insn: IType) -> Self::InstructionResult {
        Instruction::from_i_type(Opcode::LD, &dec_insn)
    }

    fn process_sd(&mut self, dec_insn: SType) -> Self::InstructionResult {
        Instruction::from_s_type(Opcode::SD, &dec_insn)
    }

    // RV64M
    fn process_mulw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::MULW, &dec_insn)
    }

    fn process_divw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::DIVW, &dec_insn)
    }

    fn process_divuw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::DIVUW, &dec_insn)
    }

    fn process_remw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::REMW, &dec_insn)
    }

    fn process_remuw(&mut self, dec_insn: RType) -> Self::InstructionResult {
        Instruction::from_r_type(Opcode::REMUW, &dec_insn)
    }

    fn process_csrrc(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrci(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrs(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrsi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrw(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_csrrwi(&mut self, _: ITypeCSR) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_fence(&mut self, _: IType) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_mret(&mut self) -> Self::InstructionResult {
        Instruction::unimp()
    }

    fn process_wfi(&mut self) -> Self::InstructionResult {
        Instruction::unimp()
    }
}

/// Transpile the [`Instruction`]s from the 32-bit encoded instructions.
///
/// `pc_base` is the guest address of `instructions_u32[0]`; slot `i` therefore sits at
/// `pc_base + 4 * i`. That address is handed to the transpiler because AUIPC is re-encoded as
/// `ADD rd, imm, pc` and needs its own address as an immediate. It is the same index the runtime
/// uses: `Program::fetch` reads slot `(pc - pc_base) / 4`, and the Program preprocessed table
/// builds row `i` with `pc = pc_base + 4 * i`.
///
/// # Panics
///
/// This function will return an error if the [`Instruction`] cannot be processed.
#[must_use]
pub(crate) fn transpile(instructions_u32: &[u32], pc_base: u64) -> Arc<[Instruction]> {
    let mut transpiler = InstructionTranspiler { pc: pc_base };
    instructions_u32
        .iter()
        .copied()
        .enumerate()
        .map(|(i, inst)| {
            transpiler.pc = pc_base + 4 * i as u64;
            process_instruction(&mut transpiler, inst)
                .unwrap_or_else(|| panic!("failed to decode instruction {inst:#010x}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrs_lib::instruction_formats::{OPCODE_AUIPC, OPCODE_LUI};

    /// Guest address of slot 0 in these fixtures. Deliberately not 0, so a transpiler that folded
    /// the slot *index* instead of the slot *address* would show up.
    const PC_BASE: u64 = 0x10000;

    /// U-type word: `imm[31:12] | rd[11:7] | opcode[6:0]`. `imm20` is the raw 20-bit field, i.e.
    /// the value the ISA shifts left by 12 before adding it to the pc.
    fn u_type_word(opcode: u32, rd: u32, imm20: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | opcode
    }

    /// `process_auipc` folds the slot's own address into the instruction, so the re-encoding is
    /// only correct if that address is `pc_base + 4 * i` and is refreshed before every decode.
    ///
    /// Nothing downstream can catch a mistake here. A wrong folded address produces a program
    /// that is *self-consistent*: the Program preprocessed table, the Cpu rows and the Add chip
    /// all read the same `op_c`, so the full verification, the CPU/GPU parity tests, the tamper
    /// battery and the pinned constraint artifact all stay green -- only the guest computing the
    /// wrong address would ever reveal it. Hence this test.
    #[test]
    fn transpile_folds_each_auipc_slots_own_address() {
        // auipc x1, 0x1000  ;  auipc x2, 0
        let words = [
            u_type_word(OPCODE_AUIPC, 1, 0x1000),
            u_type_word(OPCODE_AUIPC, 2, 0),
        ];

        let out = transpile(&words, PC_BASE);
        assert_eq!(out.len(), 2);

        // `rd = pc + (imm20 << 12)` becomes `ADD rd, imm20 << 12, pc`, two immediates.
        assert_eq!(
            out[0],
            Instruction::new(Opcode::ADD, 1, 0x0100_0000, 0x10000, true, true),
            "slot 0 must fold pc_base itself, and `imm20 << 12` must reach op_b unshifted again"
        );
        // Slot 1 pins both halves of the address: the base (0x10000, not 0) and the 4-byte
        // stride (0x10004, not 0x10001 and not 0x10000).
        assert_eq!(
            out[1],
            Instruction::new(Opcode::ADD, 2, 0, 0x10004, true, true),
            "slot 1 must fold pc_base + 4"
        );
    }

    /// The U-type immediate is sign-extended to 64 bits by `rrs_lib`, and `Instruction` stores
    /// `op_b` as a `u64` verbatim, so a negative AUIPC displacement has to survive as the
    /// two's-complement pattern and still add up correctly under `wrapping_add`.
    #[test]
    fn transpile_round_trips_a_negative_auipc_immediate() {
        // auipc x3, 0xfffff  =>  pc - 0x1000
        let words = [u_type_word(OPCODE_AUIPC, 3, 0xF_FFFF)];

        let out = transpile(&words, PC_BASE);
        assert_eq!(
            out[0],
            Instruction::new(Opcode::ADD, 3, 0xFFFF_FFFF_FFFF_F000, PC_BASE, true, true),
        );
        // What the emulator's two-immediate ADD path (and the Add chip) computes is exactly the
        // `pc.wrapping_add(imm)` the deleted AUIPC arm used to compute.
        assert_eq!(
            out[0].op_b.wrapping_add(out[0].op_c),
            PC_BASE.wrapping_sub(0x1000)
        );
    }

    /// The slot address advances per *slot*, not per AUIPC: a transpiler that bumped its `pc`
    /// field from inside `process_auipc` would pass the test above and fail here. LUI shares the
    /// U-type decode and the two-immediate ADD shape with AUIPC, so it also pins that only AUIPC
    /// reads the folded address -- LUI must stay `ADD rd, 0, imm`.
    #[test]
    fn transpile_advances_the_slot_address_over_non_auipc_slots() {
        // lui x4, 0x2  ;  addi x0, x0, 0  ;  auipc x5, 0x1
        let words = [
            u_type_word(OPCODE_LUI, 4, 0x2),
            0x0000_0013,
            u_type_word(OPCODE_AUIPC, 5, 0x1),
        ];

        let out = transpile(&words, PC_BASE);
        assert_eq!(
            out[0],
            Instruction::new(Opcode::ADD, 4, 0, 0x2000, true, true),
            "LUI must not pick up the slot address"
        );
        assert_eq!(
            out[2],
            Instruction::new(Opcode::ADD, 5, 0x1000, PC_BASE + 8, true, true),
            "slot 2 must fold pc_base + 8 even though slots 0 and 1 are not AUIPC"
        );
    }
}
