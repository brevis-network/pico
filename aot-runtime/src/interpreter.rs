//! Interpreter Fallback for AOT Emulation
//!
//! This module provides interpreter-based execution for code paths that
//! cannot be handled by AOT-compiled blocks (e.g., dynamic jumps to
//! addresses not known at compile time).

use super::{emulator::AotEmulatorCore, NextStep};
use pico_vm::{
    compiler::riscv::{instruction::Instruction, opcode::Opcode},
    emulator::riscv::memory::VALUES_SIZE,
};

impl AotEmulatorCore {
    #[inline(always)]
    fn interpreter_shift_amount_u32(value: u64) -> u32 {
        (value & 0x3f) as u32
    }

    /// Fallback interpreter loop - used when AOT blocks are not available.
    #[cold]
    #[inline(never)]
    pub fn interpret_from_current_pc(&mut self) -> Result<NextStep, String> {
        loop {
            if self.pc == 0 {
                return Ok(NextStep::Halt);
            }
            let pc = self.pc;
            let inst = self.fetch_instruction(pc)?;
            if let Some(step) = self.execute_interpreter_instruction(pc, inst)? {
                return Ok(step);
            }
            if let Some(func) = self.lookup_block(self.pc) {
                return Ok(NextStep::Direct(func));
            }
        }
    }

    #[doc(hidden)]
    pub fn debug_interpret_single_step(&mut self) -> Result<(), String> {
        if self.pc == 0 {
            return Ok(());
        }
        let pc = self.pc;
        let inst = self.fetch_instruction(pc)?;
        let _ = self.execute_interpreter_instruction(pc, inst)?;
        Ok(())
    }

    /// Execute a single instruction via the interpreter.
    #[cold]
    #[inline(never)]
    fn execute_interpreter_instruction(
        &mut self,
        pc: u64,
        inst: Instruction,
    ) -> Result<Option<NextStep>, String> {
        use Opcode::*;
        match inst.opcode {
            JAL => Ok(Some(self.interpret_jal(pc, &inst)?)),
            JALR => Ok(Some(self.interpret_jalr(pc, &inst)?)),
            BEQ | BNE | BLT | BGE | BLTU | BGEU => Ok(Some(self.interpret_branch(pc, &inst)?)),
            ECALL => Ok(Some(self.interpret_ecall(pc)?)),
            EBREAK => Err("Breakpoint".to_string()),
            UNIMP => {
                self.update_insn_clock();
                Err(format!("Unimplemented instruction (UNIMP) at PC {:#x}", pc))
            }
            ADD => self.exec_rr_imm_op(pc, &inst, |b, c| b.wrapping_add(c)),
            SUB => self.exec_rr_imm_op(pc, &inst, |b, c| b.wrapping_sub(c)),
            XOR => self.exec_rr_imm_op(pc, &inst, |b, c| b ^ c),
            OR => self.exec_rr_imm_op(pc, &inst, |b, c| b | c),
            AND => self.exec_rr_imm_op(pc, &inst, |b, c| b & c),
            SLL => self.exec_rr_imm_op(pc, &inst, |b, c| {
                b.wrapping_shl(Self::interpreter_shift_amount_u32(c))
            }),
            SRL => self.exec_rr_imm_op(pc, &inst, |b, c| {
                b.wrapping_shr(Self::interpreter_shift_amount_u32(c))
            }),
            SRA => self.exec_rr_imm_op(pc, &inst, |b, c| {
                (b as i64).wrapping_shr(Self::interpreter_shift_amount_u32(c)) as u64
            }),
            SLT => self.exec_rr_imm_op(
                pc,
                &inst,
                |b, c| {
                    if (b as i64) < (c as i64) {
                        1
                    } else {
                        0
                    }
                },
            ),
            SLTU => self.exec_rr_imm_op(pc, &inst, |b, c| if b < c { 1 } else { 0 }),
            AUIPC => self.interpret_auipc(pc, &inst),
            LB | LH | LW | LBU | LHU | LWU | LD => self.interpret_load(pc, &inst),
            SB | SH | SW | SD => self.interpret_store(pc, &inst),
            MUL => self.exec_rr_imm_op(pc, &inst, |b, c| b.wrapping_mul(c)),
            MULH => self.interpret_mul_high(pc, &inst, true, true),
            MULHU => self.interpret_mul_high(pc, &inst, false, false),
            MULHSU => self.interpret_mul_high(pc, &inst, true, false),
            DIV => self.interpret_div(pc, &inst, true),
            DIVU => self.interpret_div(pc, &inst, false),
            REM => self.interpret_rem(pc, &inst, true),
            REMU => self.interpret_rem(pc, &inst, false),
            ADDW | SUBW | SLLW | SRLW | SRAW | MULW | DIVW | DIVUW | REMW | REMUW => {
                self.interpret_word_op(pc, &inst)
            }
        }
    }

    /// Helper: compute NextStep for a given PC.
    #[inline(always)]
    fn direct_or_dynamic(&self, pc: u64) -> NextStep {
        if let Some(func) = self.lookup_block(pc) {
            NextStep::Direct(func)
        } else {
            NextStep::Dynamic(pc)
        }
    }

    /// Helper: finish an interpreter step and check for yield.
    #[inline(always)]
    fn finish_interpreter_step(&mut self) -> Option<NextStep> {
        self.check_chunk_boundary();
        if self.should_yield() {
            Some(NextStep::Dynamic(self.pc))
        } else {
            None
        }
    }

    /// Fetch an instruction from the program.
    #[inline(always)]
    pub(crate) fn fetch_instruction(&self, pc: u64) -> Result<Instruction, String> {
        let pc_base = self.program.pc_base;
        if pc < pc_base {
            return Err(format!("PC {:#x} before program base {:#x}", pc, pc_base));
        }
        let offset = pc.wrapping_sub(pc_base);
        if !offset.is_multiple_of(4) {
            return Err(format!("Unaligned PC {:#x}", pc));
        }
        let idx = usize::try_from(offset / 4)
            .map_err(|_| format!("PC {:#x} instruction index does not fit usize", pc))?;
        self.program
            .instructions
            .get(idx)
            .copied()
            .ok_or_else(|| format!("PC {:#x} outside program", pc))
    }

    /// Decode register-register or register-immediate instruction operands.
    #[inline(always)]
    fn decode_rr_imm(inst: &Instruction) -> (usize, usize, usize, u64, bool) {
        if !inst.imm_c {
            let (rd, rs1, rs2) = inst.r_type();
            (rd as usize, rs1 as usize, rs2 as usize, 0, false)
        } else {
            let (rd, rs1, imm) = inst.i_type();
            (rd as usize, rs1 as usize, 0, imm, true)
        }
    }

    /// Execute a register-register or register-immediate ALU operation.
    #[inline(always)]
    fn exec_rr_imm_op<F>(
        &mut self,
        pc: u64,
        inst: &Instruction,
        mut op: F,
    ) -> Result<Option<NextStep>, String>
    where
        F: FnMut(u64, u64) -> u64,
    {
        if inst.imm_b && inst.imm_c {
            let rd = inst.op_a as usize;
            let lhs = inst.op_b;
            let rhs = inst.op_c;
            let value = op(lhs, rhs);
            self.write_reg(rd, value);
            self.pc = pc.wrapping_add(4);
            self.update_insn_clock();
            return Ok(self.finish_interpreter_step());
        }
        let (rd, rs1, rs2, imm, use_imm) = Self::decode_rr_imm(inst);
        let rhs = if use_imm { imm } else { self.read_reg_c(rs2) };
        let lhs = self.read_reg_b(rs1);
        let value = op(lhs, rhs);
        self.write_reg(rd, value);
        self.pc = pc.wrapping_add(4);
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    #[inline(always)]
    fn finish_word_op(&mut self) -> Result<Option<NextStep>, String> {
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    #[inline(always)]
    fn decode_word_rr_imm(&mut self, inst: &Instruction) -> (usize, u64, u64) {
        if !inst.imm_c {
            let (rd, rs1, rs2) = inst.r_type();
            (
                rd as usize,
                self.read_reg_b(rs1 as usize),
                self.read_reg_c(rs2 as usize),
            )
        } else if !inst.imm_b {
            let (rd, rs1, imm) = inst.i_type();
            (rd as usize, self.read_reg_b(rs1 as usize), imm)
        } else {
            (inst.op_a as usize, inst.op_b, inst.op_c)
        }
    }

    #[inline(always)]
    fn interpret_word_op(
        &mut self,
        pc: u64,
        inst: &Instruction,
    ) -> Result<Option<NextStep>, String> {
        let (rd, lhs, rhs) = self.decode_word_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);

        match inst.opcode {
            Opcode::ADDW => {
                let value = u64::from((lhs as u32).wrapping_add(rhs as u32));
                self.write_reg(rd, Self::sign_extend_word_result_u64(value));
                self.pc = next_pc;
            }
            Opcode::SUBW => {
                let value = u64::from((lhs as u32).wrapping_sub(rhs as u32));
                self.write_reg(rd, Self::sign_extend_word_result_u64(value));
                self.pc = next_pc;
            }
            Opcode::SLLW => {
                let shamt = Self::word_shift_amount_u32(rhs);
                let value = u64::from((lhs as u32).wrapping_shl(shamt));
                self.write_reg(rd, Self::sign_extend_word_result_u64(value));
                self.pc = next_pc;
            }
            Opcode::SRLW => {
                let shamt = Self::word_shift_amount_u32(rhs);
                let value = u64::from((lhs as u32).wrapping_shr(shamt));
                self.write_reg(rd, Self::sign_extend_word_result_u64(value));
                self.pc = next_pc;
            }
            Opcode::SRAW => {
                let shamt = Self::word_shift_amount_u32(rhs);
                let value = (lhs as u32 as i32).wrapping_shr(shamt);
                self.write_reg(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
                self.pc = next_pc;
            }
            Opcode::MULW => {
                let value = u64::from((lhs as u32).wrapping_mul(rhs as u32));
                self.write_reg(rd, Self::sign_extend_word_result_u64(value));
                self.pc = next_pc;
            }
            Opcode::DIVW => {
                let lhs = lhs as u32 as i32;
                let rhs = rhs as u32 as i32;
                let value = if rhs == 0 {
                    -1i32
                } else if lhs == i32::MIN && rhs == -1 {
                    i32::MIN
                } else {
                    lhs.wrapping_div(rhs)
                };
                self.write_reg(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
                self.pc = next_pc;
            }
            Opcode::DIVUW => {
                let lhs = lhs as u32;
                let rhs = rhs as u32;
                let value = if rhs == 0 {
                    u32::MAX
                } else {
                    lhs.wrapping_div(rhs)
                };
                self.write_reg(rd, Self::sign_extend_word_result_u64(u64::from(value)));
                self.pc = next_pc;
            }
            Opcode::REMW => {
                let lhs = lhs as u32 as i32;
                let rhs = rhs as u32 as i32;
                let value = if rhs == 0 {
                    lhs
                } else if lhs == i32::MIN && rhs == -1 {
                    0
                } else {
                    lhs.wrapping_rem(rhs)
                };
                self.write_reg(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
                self.pc = next_pc;
            }
            Opcode::REMUW => {
                let lhs = lhs as u32;
                let rhs = rhs as u32;
                let value = if rhs == 0 { lhs } else { lhs.wrapping_rem(rhs) };
                self.write_reg(rd, Self::sign_extend_word_result_u64(u64::from(value)));
                self.pc = next_pc;
            }
            _ => unreachable!(),
        }

        self.finish_word_op()
    }

    /// Interpret JAL instruction.
    fn interpret_jal(&mut self, pc: u64, inst: &Instruction) -> Result<NextStep, String> {
        let (rd, imm) = inst.j_type();
        let return_addr = pc.wrapping_add(4);
        let target = pc.wrapping_add(imm);
        self.write_reg(rd as usize, return_addr);
        self.pc = target;
        self.update_insn_clock();
        if let Some(step) = self.finish_interpreter_step() {
            return Ok(step);
        }
        Ok(self.direct_or_dynamic(target))
    }

    /// Interpret JALR instruction.
    fn interpret_jalr(&mut self, pc: u64, inst: &Instruction) -> Result<NextStep, String> {
        let (rd, rs1, imm) = inst.i_type();
        let return_addr = pc.wrapping_add(4);
        let base = self.read_reg_b(rs1 as usize);
        let target = base.wrapping_add(imm) & !1_u64;
        self.write_reg(rd as usize, return_addr);
        self.pc = target;
        self.update_insn_clock();
        if let Some(step) = self.finish_interpreter_step() {
            return Ok(step);
        }
        Ok(NextStep::Dynamic(target))
    }

    /// Interpret branch instructions.
    fn interpret_branch(&mut self, pc: u64, inst: &Instruction) -> Result<NextStep, String> {
        let (rs1, rs2, imm) = inst.b_type();
        let rhs = self.read_reg_b(rs2 as usize);
        let lhs = self.read_reg_a(rs1 as usize);
        let target = pc.wrapping_add(imm);
        let fallthrough = pc.wrapping_add(4);
        let cond = match inst.opcode {
            Opcode::BEQ => lhs == rhs,
            Opcode::BNE => lhs != rhs,
            Opcode::BLT => (lhs as i64) < (rhs as i64),
            Opcode::BGE => (lhs as i64) >= (rhs as i64),
            Opcode::BLTU => lhs < rhs,
            Opcode::BGEU => lhs >= rhs,
            _ => false,
        };
        self.pc = if cond { target } else { fallthrough };
        self.update_insn_clock();
        if let Some(step) = self.finish_interpreter_step() {
            return Ok(step);
        }
        Ok(self.direct_or_dynamic(self.pc))
    }

    /// Interpret AUIPC instruction.
    fn interpret_auipc(&mut self, pc: u64, inst: &Instruction) -> Result<Option<NextStep>, String> {
        let (rd, imm) = inst.u_type();
        let next_pc = pc.wrapping_add(4);
        let value = pc.wrapping_add(imm);
        self.write_reg(rd as usize, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret load instructions.
    fn interpret_load(&mut self, pc: u64, inst: &Instruction) -> Result<Option<NextStep>, String> {
        let next_pc = pc.wrapping_add(4);
        let (rd, rs1, imm) = inst.i_type();
        let rd = rd as usize;
        let base = self.read_reg_b(rs1 as usize);
        let addr = base.wrapping_add(imm);
        let max_addr = match inst.opcode {
            Opcode::LD => (VALUES_SIZE - 8) as u64,
            Opcode::LW | Opcode::LWU => (VALUES_SIZE - 4) as u64,
            Opcode::LH | Opcode::LHU => (VALUES_SIZE - 2) as u64,
            Opcode::LB | Opcode::LBU => (VALUES_SIZE - 1) as u64,
            _ => unreachable!(),
        };
        if addr > max_addr {
            return Err(format!(
                "Interpreter {:?} at PC {pc:#x} produced out-of-range addr {addr:#x} (base {base:#x}, imm {imm:#x})",
                inst.opcode
            ));
        }
        let value = match inst.opcode {
            Opcode::LB => {
                let word = self.read_mem_dword(Self::dword_addr(addr));
                let byte = Self::read_u8_from_word(word, addr) as i8;
                byte as i64 as u64
            }
            Opcode::LH => {
                if !addr.is_multiple_of(2) {
                    return Err(format!("Unaligned halfword access at {:#x}", addr));
                }
                let word = self.read_mem_dword(Self::dword_addr(addr));
                let raw = Self::read_u16_from_word(word, addr);
                (raw as i16) as i64 as u64
            }
            Opcode::LW => {
                if !addr.is_multiple_of(4) {
                    return Err(format!("Unaligned word access at {:#x}", addr));
                }
                let word = self.read_mem_word(addr);
                (word as u32 as i32) as i64 as u64
            }
            Opcode::LWU => {
                if !addr.is_multiple_of(4) {
                    return Err(format!("Unaligned word access at {:#x}", addr));
                }
                self.read_mem_word(addr)
            }
            Opcode::LD => {
                if !addr.is_multiple_of(8) {
                    return Err(format!("Unaligned doubleword access at {:#x}", addr));
                }
                self.read_mem_dword(addr)
            }
            Opcode::LBU => {
                let word = self.read_mem_dword(Self::dword_addr(addr));
                u64::from(Self::read_u8_from_word(word, addr))
            }
            Opcode::LHU => {
                if !addr.is_multiple_of(2) {
                    return Err(format!("Unaligned halfword access at {:#x}", addr));
                }
                let word = self.read_mem_dword(Self::dword_addr(addr));
                u64::from(Self::read_u16_from_word(word, addr))
            }
            _ => unreachable!(),
        };
        self.write_reg(rd, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret store instructions.
    fn interpret_store(&mut self, pc: u64, inst: &Instruction) -> Result<Option<NextStep>, String> {
        let next_pc = pc.wrapping_add(4);
        let (rs2, rs1, imm) = inst.s_type();
        let value = self.read_reg_a(rs2 as usize);
        let base = self.read_reg_b(rs1 as usize);
        let addr = base.wrapping_add(imm);
        let max_addr = match inst.opcode {
            Opcode::SD => (VALUES_SIZE - 8) as u64,
            Opcode::SW => (VALUES_SIZE - 4) as u64,
            Opcode::SH => (VALUES_SIZE - 2) as u64,
            Opcode::SB => (VALUES_SIZE - 1) as u64,
            _ => unreachable!(),
        };
        if addr > max_addr {
            return Err(format!(
                "Interpreter {:?} at PC {pc:#x} produced out-of-range addr {addr:#x} (base {base:#x}, imm {imm:#x}, value {value:#x})",
                inst.opcode
            ));
        }
        match inst.opcode {
            Opcode::SB => {
                let word_addr = Self::dword_addr(addr);
                let word = self.read_mem_dword(word_addr);
                let new_word = Self::write_u8_into_word(word, addr, value);
                self.write_mem_dword(word_addr, new_word);
            }
            Opcode::SH => {
                if !addr.is_multiple_of(2) {
                    return Err(format!("Unaligned halfword store at {:#x}", addr));
                }
                let word_addr = Self::dword_addr(addr);
                let word = self.read_mem_dword(word_addr);
                let new_word = Self::write_u16_into_word(word, addr, value);
                self.write_mem_dword(word_addr, new_word);
            }
            Opcode::SW => {
                if !addr.is_multiple_of(4) {
                    return Err(format!("Unaligned word store at {:#x}", addr));
                }
                self.write_mem_word(addr, value);
            }
            Opcode::SD => {
                if !addr.is_multiple_of(8) {
                    return Err(format!("Unaligned doubleword store at {:#x}", addr));
                }
                self.write_mem_dword(addr, value);
            }
            _ => unreachable!(),
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret MULH/MULHU/MULHSU instructions.
    fn interpret_mul_high(
        &mut self,
        pc: u64,
        inst: &Instruction,
        lhs_signed: bool,
        rhs_signed: bool,
    ) -> Result<Option<NextStep>, String> {
        let (rd, rs1, rs2, _, _) = Self::decode_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);
        let rhs = self.read_reg_c(rs2);
        let lhs = self.read_reg_b(rs1);
        let prod = if lhs_signed && rhs_signed {
            Self::rv64_mulh_result_u64(lhs, rhs)
        } else if lhs_signed {
            Self::rv64_mulhsu_result_u64(lhs, rhs)
        } else {
            Self::rv64_mulhu_result_u64(lhs, rhs)
        };
        self.write_reg(rd, prod);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret DIV/DIVU instructions.
    fn interpret_div(
        &mut self,
        pc: u64,
        inst: &Instruction,
        signed: bool,
    ) -> Result<Option<NextStep>, String> {
        let (rd, rs1, rs2, _, _) = Self::decode_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);
        let result = if signed {
            Self::rv64_div_result_u64(self.read_reg_b(rs1), self.read_reg_c(rs2))
        } else {
            Self::rv64_divu_result_u64(self.read_reg_b(rs1), self.read_reg_c(rs2))
        };
        self.write_reg(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret REM/REMU instructions.
    fn interpret_rem(
        &mut self,
        pc: u64,
        inst: &Instruction,
        signed: bool,
    ) -> Result<Option<NextStep>, String> {
        let (rd, rs1, rs2, _, _) = Self::decode_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);
        let result = if signed {
            Self::rv64_rem_result_u64(self.read_reg_b(rs1), self.read_reg_c(rs2))
        } else {
            Self::rv64_remu_result_u64(self.read_reg_b(rs1), self.read_reg_c(rs2))
        };
        self.write_reg(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret ECALL instruction.
    pub(crate) fn interpret_ecall(&mut self, pc: u64) -> Result<NextStep, String> {
        let _next_pc = pc.wrapping_add(4);
        let syscall_id = self.read_reg_snapshot(5);
        let arg2 = self.read_reg_c(11);
        let arg1 = self.read_reg_b(10);

        match self.execute_syscall(syscall_id, arg1, arg2) {
            Ok((return_value, new_next_pc, extra_cycles, should_halt)) => {
                self.write_reg(5, return_value);
                self.pc = new_next_pc;
                self.update_insn_clock();

                if extra_cycles > 0 {
                    self.clk = self.clk.wrapping_add(extra_cycles);
                }

                if should_halt {
                    self.check_chunk_boundary();
                    return Ok(NextStep::Halt);
                }

                self.check_chunk_boundary();
                if self.should_yield() {
                    return Ok(NextStep::Dynamic(self.pc));
                }

                Ok(self.direct_or_dynamic(self.pc))
            }
            Err(e) => Err(e),
        }
    }
}
