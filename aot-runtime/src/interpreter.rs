//! Interpreter Fallback for AOT Emulation
//!
//! This module provides interpreter-based execution for code paths that
//! cannot be handled by AOT-compiled blocks (e.g., dynamic jumps to
//! addresses not known at compile time).

use super::{emulator::AotEmulatorCore, NextStep};
use pico_vm::compiler::riscv::{instruction::Instruction, opcode::Opcode};

impl AotEmulatorCore {
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

    /// Execute a single instruction via the interpreter.
    #[cold]
    #[inline(never)]
    fn execute_interpreter_instruction(
        &mut self,
        pc: u32,
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
            SLL => self.exec_rr_imm_op(pc, &inst, |b, c| b.wrapping_shl(c & 0x1f)),
            SRL => self.exec_rr_imm_op(pc, &inst, |b, c| b.wrapping_shr(c & 0x1f)),
            SRA => {
                self.exec_rr_imm_op(pc, &inst, |b, c| ((b as i32).wrapping_shr(c & 0x1f)) as u32)
            }
            SLT => self.exec_rr_imm_op(
                pc,
                &inst,
                |b, c| {
                    if (b as i32) < (c as i32) {
                        1
                    } else {
                        0
                    }
                },
            ),
            SLTU => self.exec_rr_imm_op(pc, &inst, |b, c| if b < c { 1 } else { 0 }),
            AUIPC => self.interpret_auipc(pc, &inst),
            LB | LH | LW | LBU | LHU => self.interpret_load(pc, &inst),
            SB | SH | SW => self.interpret_store(pc, &inst),
            MUL => self.exec_rr_imm_op(pc, &inst, |b, c| b.wrapping_mul(c)),
            MULH => self.interpret_mul_high(pc, &inst, true, true),
            MULHU => self.interpret_mul_high(pc, &inst, false, false),
            MULHSU => self.interpret_mul_high(pc, &inst, true, false),
            DIV => self.interpret_div(pc, &inst, true),
            DIVU => self.interpret_div(pc, &inst, false),
            REM => self.interpret_rem(pc, &inst, true),
            REMU => self.interpret_rem(pc, &inst, false),
        }
    }

    /// Helper: compute NextStep for a given PC.
    #[inline(always)]
    fn direct_or_dynamic(&self, pc: u32) -> NextStep {
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
    pub(crate) fn fetch_instruction(&self, pc: u32) -> Result<Instruction, String> {
        if pc < self.program.pc_base {
            return Err(format!(
                "PC {:#x} before program base {:#x}",
                pc, self.program.pc_base
            ));
        }
        let offset = pc.wrapping_sub(self.program.pc_base);
        if !offset.is_multiple_of(4) {
            return Err(format!("Unaligned PC {:#x}", pc));
        }
        let idx = (offset / 4) as usize;
        self.program
            .instructions
            .get(idx)
            .copied()
            .ok_or_else(|| format!("PC {:#x} outside program", pc))
    }

    /// Decode register-register or register-immediate instruction operands.
    #[inline(always)]
    fn decode_rr_imm(inst: &Instruction) -> (usize, usize, usize, u32, bool) {
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
        pc: u32,
        inst: &Instruction,
        mut op: F,
    ) -> Result<Option<NextStep>, String>
    where
        F: FnMut(u32, u32) -> u32,
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

    /// Interpret JAL instruction.
    fn interpret_jal(&mut self, pc: u32, inst: &Instruction) -> Result<NextStep, String> {
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
    fn interpret_jalr(&mut self, pc: u32, inst: &Instruction) -> Result<NextStep, String> {
        let (rd, rs1, imm) = inst.i_type();
        let return_addr = pc.wrapping_add(4);
        let base = self.read_reg_b(rs1 as usize);
        // Note: simple mode does NOT apply the & !1 mask per RISC-V spec,
        // so AOT must match that behavior for drop-in replacement.
        let target = base.wrapping_add(imm);
        self.write_reg(rd as usize, return_addr);
        self.pc = target;
        self.update_insn_clock();
        if let Some(step) = self.finish_interpreter_step() {
            return Ok(step);
        }
        Ok(NextStep::Dynamic(target))
    }

    /// Interpret branch instructions.
    fn interpret_branch(&mut self, pc: u32, inst: &Instruction) -> Result<NextStep, String> {
        let (rs1, rs2, imm) = inst.b_type();
        let rhs = self.read_reg_b(rs2 as usize);
        let lhs = self.read_reg_a(rs1 as usize);
        let target = pc.wrapping_add(imm);
        let fallthrough = pc.wrapping_add(4);
        let cond = match inst.opcode {
            Opcode::BEQ => lhs == rhs,
            Opcode::BNE => lhs != rhs,
            Opcode::BLT => (lhs as i32) < (rhs as i32),
            Opcode::BGE => (lhs as i32) >= (rhs as i32),
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
    fn interpret_auipc(&mut self, pc: u32, inst: &Instruction) -> Result<Option<NextStep>, String> {
        let (rd, imm) = inst.u_type();
        let next_pc = pc.wrapping_add(4);
        let value = self.pc.wrapping_add(imm);
        self.write_reg(rd as usize, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret load instructions.
    fn interpret_load(&mut self, pc: u32, inst: &Instruction) -> Result<Option<NextStep>, String> {
        let next_pc = pc.wrapping_add(4);
        let (rd, rs1, imm) = inst.i_type();
        let rd = rd as usize;
        let base = self.read_reg_b(rs1 as usize);
        let addr = base.wrapping_add(imm);
        let value = match inst.opcode {
            Opcode::LB => {
                let word_addr = addr & !3;
                let word = self.read_mem(word_addr);
                let byte_idx = (addr % 4) as usize;
                let byte = word.to_le_bytes()[byte_idx] as i8;
                byte as i32 as u32
            }
            Opcode::LH => {
                if !addr.is_multiple_of(2) {
                    return Err(format!("Unaligned halfword access at {:#x}", addr));
                }
                let word_addr = addr & !3;
                let word = self.read_mem(word_addr);
                let halfword_idx = ((addr >> 1) % 2) as usize;
                let raw = match halfword_idx {
                    0 => word & 0x0000_FFFF,
                    1 => (word & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                } as u16;
                (raw as i16) as i32 as u32
            }
            Opcode::LW => {
                if !addr.is_multiple_of(4) {
                    return Err(format!("Unaligned word access at {:#x}", addr));
                }
                self.read_mem(addr)
            }
            Opcode::LBU => {
                let word_addr = addr & !3;
                let word = self.read_mem(word_addr);
                let byte_idx = (addr % 4) as usize;
                word.to_le_bytes()[byte_idx] as u32
            }
            Opcode::LHU => {
                if !addr.is_multiple_of(2) {
                    return Err(format!("Unaligned halfword access at {:#x}", addr));
                }
                let word_addr = addr & !3;
                let word = self.read_mem(word_addr);
                let halfword_idx = ((addr >> 1) % 2) as usize;
                match halfword_idx {
                    0 => word & 0x0000_FFFF,
                    1 => (word & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        };
        self.write_reg(rd, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret store instructions.
    fn interpret_store(&mut self, pc: u32, inst: &Instruction) -> Result<Option<NextStep>, String> {
        let next_pc = pc.wrapping_add(4);
        let (rs2, rs1, imm) = inst.s_type();
        let value = self.read_reg_a(rs2 as usize);
        let base = self.read_reg_b(rs1 as usize);
        let addr = base.wrapping_add(imm);
        match inst.opcode {
            Opcode::SB => {
                let word_addr = addr & !3;
                let mut word = self.read_mem(word_addr);
                let byte_shift = (addr % 4) * 8;
                let mask = !(0xFF_u32 << byte_shift);
                word = (word & mask) | ((value & 0xFF) << byte_shift);
                self.write_mem(word_addr, word);
            }
            Opcode::SH => {
                if !addr.is_multiple_of(2) {
                    return Err(format!("Unaligned halfword store at {:#x}", addr));
                }
                let word_addr = addr & !3;
                let mut word = self.read_mem(word_addr);
                let half_idx = ((addr >> 1) % 2) * 16;
                let mask = !(0xFFFF_u32 << half_idx);
                word = (word & mask) | ((value & 0xFFFF) << half_idx);
                self.write_mem(word_addr, word);
            }
            Opcode::SW => {
                if !addr.is_multiple_of(4) {
                    return Err(format!("Unaligned word store at {:#x}", addr));
                }
                self.write_mem(addr, value);
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
        pc: u32,
        inst: &Instruction,
        lhs_signed: bool,
        rhs_signed: bool,
    ) -> Result<Option<NextStep>, String> {
        let (rd, rs1, rs2, _, _) = Self::decode_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);
        let rhs = if rhs_signed {
            self.read_reg_c(rs2) as i32 as i64
        } else {
            self.read_reg_c(rs2) as u64 as i64
        };
        let lhs = if lhs_signed {
            self.read_reg_b(rs1) as i32 as i64
        } else {
            self.read_reg_b(rs1) as u64 as i64
        };
        let prod = lhs.wrapping_mul(rhs);
        self.write_reg(rd, (prod >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret DIV/DIVU instructions.
    fn interpret_div(
        &mut self,
        pc: u32,
        inst: &Instruction,
        signed: bool,
    ) -> Result<Option<NextStep>, String> {
        let (rd, rs1, rs2, _, _) = Self::decode_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);
        let result = if signed {
            let rhs = self.read_reg_c(rs2) as i32;
            let lhs = self.read_reg_b(rs1) as i32;
            if rhs == 0 {
                u32::MAX
            } else {
                lhs.wrapping_div(rhs) as u32
            }
        } else {
            let rhs = self.read_reg_c(rs2);
            let lhs = self.read_reg_b(rs1);
            if rhs == 0 {
                u32::MAX
            } else {
                lhs.wrapping_div(rhs)
            }
        };
        self.write_reg(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret REM/REMU instructions.
    fn interpret_rem(
        &mut self,
        pc: u32,
        inst: &Instruction,
        signed: bool,
    ) -> Result<Option<NextStep>, String> {
        let (rd, rs1, rs2, _, _) = Self::decode_rr_imm(inst);
        let next_pc = pc.wrapping_add(4);
        let result = if signed {
            let rhs = self.read_reg_c(rs2) as i32;
            let lhs = self.read_reg_b(rs1) as i32;
            if rhs == 0 {
                lhs as u32
            } else {
                lhs.wrapping_rem(rhs) as u32
            }
        } else {
            let rhs = self.read_reg_c(rs2);
            let lhs = self.read_reg_b(rs1);
            if rhs == 0 {
                lhs
            } else {
                lhs.wrapping_rem(rhs)
            }
        };
        self.write_reg(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(self.finish_interpreter_step())
    }

    /// Interpret ECALL instruction.
    pub(crate) fn interpret_ecall(&mut self, pc: u32) -> Result<NextStep, String> {
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
