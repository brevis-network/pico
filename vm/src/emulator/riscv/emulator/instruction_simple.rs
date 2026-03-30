use super::{align_u64, EmulationError, RiscvEmulator};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, register::Register},
    emulator::riscv::syscalls::{syscall_context::SyscallContext, SyscallCode},
};
use tracing::debug;

#[inline(always)]
fn invalid_memory_addr_u64_simple(addr: u64, context: &str) -> u64 {
    let _ = context;
    addr
}

impl RiscvEmulator {
    #[inline(always)]
    fn w_alu_rr_simple(&mut self, instruction: &Instruction) -> (Register, u64, u64) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr_simple(rs2, MemoryAccessPosition::C);
            let b = self.rr_simple(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b {
            let (rd, rs1, imm) = instruction.i_type();
            (rd, self.rr_simple(rs1, MemoryAccessPosition::B), imm)
        } else {
            debug_assert!(instruction.imm_b && instruction.imm_c);
            (
                Register::from_u8(instruction.op_a),
                instruction.op_b,
                instruction.op_c,
            )
        }
    }

    /// Emulate the given instruction over the current state.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn emulate_instruction_simple(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), EmulationError> {
        let mut next_pc = self.state.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u64, u64, u64);
        let (addr, memory_read_value): (u64, u64);

        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b.wrapping_add(c);
                self.alu_rw_simple(rd, a);
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b.wrapping_sub(c);
                self.alu_rw_simple(rd, a);
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b ^ c;
                self.alu_rw_simple(rd, a);
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b | c;
                self.alu_rw_simple(rd, a);
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b & c;
                self.alu_rw_simple(rd, a);
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b.wrapping_shl((c & 0x3f) as u32);
                self.alu_rw_simple(rd, a);
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b.wrapping_shr((c & 0x3f) as u32);
                self.alu_rw_simple(rd, a);
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = (b as i64).wrapping_shr((c & 0x3f) as u32) as u64;
                self.alu_rw_simple(rd, a);
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = if (b as i64) < (c as i64) { 1 } else { 0 };
                self.alu_rw_simple(rd, a);
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = if b < c { 1 } else { 0 };
                self.alu_rw_simple(rd, a);
            }

            // Load instructions.
            Opcode::LB => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                let value = memory_read_value.to_le_bytes()[(addr % 8) as usize];
                a = ((value as i8) as i64) as u64;
                self.rw_simple(rd, a);
            }
            Opcode::LH => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LH,
                        invalid_memory_addr_u64_simple(addr, "lh"),
                    ));
                }
                let shift = ((addr / 2) % 4) * 16;
                let value = ((memory_read_value >> shift) & 0xFFFF) as u16;
                a = ((value as i16) as i64) as u64;
                self.rw_simple(rd, a);
            }
            Opcode::LW => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LW,
                        invalid_memory_addr_u64_simple(addr, "lw"),
                    ));
                }
                let shift = ((addr / 4) % 2) * 32;
                let value = ((memory_read_value >> shift) & 0xFFFF_FFFF) as u32;
                a = (value as i32 as i64) as u64;
                self.rw_simple(rd, a);
            }
            Opcode::LBU => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                let value = memory_read_value.to_le_bytes()[(addr % 8) as usize];
                a = u64::from(value);
                self.rw_simple(rd, a);
            }
            Opcode::LHU => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LHU,
                        invalid_memory_addr_u64_simple(addr, "lhu"),
                    ));
                }
                let shift = ((addr / 2) % 4) * 16;
                let value = ((memory_read_value >> shift) & 0xFFFF) as u16;
                a = u64::from(value);
                self.rw_simple(rd, a);
            }
            Opcode::LWU => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LWU,
                        invalid_memory_addr_u64_simple(addr, "lwu"),
                    ));
                }
                let shift = ((addr / 4) % 2) * 32;
                a = ((memory_read_value >> shift) & 0xFFFF_FFFF) as u32 as u64;
                self.rw_simple(rd, a);
            }
            Opcode::LD => {
                (rd, _, _, addr, memory_read_value) = self.load_rr_simple(instruction);
                if addr % 8 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LD,
                        invalid_memory_addr_u64_simple(addr, "ld"),
                    ));
                }
                self.rw_simple(rd, memory_read_value);
            }

            // Store instructions.
            Opcode::SB => {
                (a, _, _, addr, memory_read_value) = self.store_rr_simple(instruction);
                let shift = (addr % 8) * 8;
                let mask = 0xFFu64 << shift;
                let value = (memory_read_value & !mask) | ((a & 0xFF) << shift);
                self.mw_cpu_simple(align_u64(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SH => {
                (a, _, _, addr, memory_read_value) = self.store_rr_simple(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::SH,
                        invalid_memory_addr_u64_simple(addr, "sh"),
                    ));
                }
                let shift = ((addr / 2) % 4) * 16;
                let mask = 0xFFFFu64 << shift;
                let value = (memory_read_value & !mask) | ((a & 0xFFFF) << shift);
                self.mw_cpu_simple(align_u64(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SW => {
                (a, _, _, addr, memory_read_value) = self.store_rr_simple(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::SW,
                        invalid_memory_addr_u64_simple(addr, "sw"),
                    ));
                }
                let shift = ((addr / 4) % 2) * 32;
                let mask = 0xFFFF_FFFFu64 << shift;
                let value = (memory_read_value & !mask) | ((a & 0xFFFF_FFFF) << shift);
                self.mw_cpu_simple(align_u64(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SD => {
                let (rs1, rs2, imm) = instruction.s_type();
                c = imm;
                b = self.rr_simple(rs2, MemoryAccessPosition::B);
                let store_value = self.rr_simple(rs1, MemoryAccessPosition::A);
                addr = b.wrapping_add(c);
                if addr % 8 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::SD,
                        invalid_memory_addr_u64_simple(addr, "sd"),
                    ));
                }
                self.mw_cpu_simple(align_u64(addr), store_value, MemoryAccessPosition::Memory);
            }

            // B-type instructions.
            Opcode::BEQ => {
                (a, b, c) = self.branch_rr_simple(instruction);
                if a == b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                (a, b, c) = self.branch_rr_simple(instruction);
                if a != b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLT => {
                (a, b, c) = self.branch_rr_simple(instruction);
                if (a as i64) < (b as i64) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr_simple(instruction);
                if (a as i64) >= (b as i64) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLTU => {
                (a, b, c) = self.branch_rr_simple(instruction);
                if a < b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGEU => {
                (a, b, c) = self.branch_rr_simple(instruction);
                if a >= b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (_, _) = (imm, 0);
                a = self.state.pc.wrapping_add(4);
                self.rw_simple(rd, a);
                next_pc = self.state.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr_simple(rs1, MemoryAccessPosition::B), imm);
                a = self.state.pc.wrapping_add(4);
                self.rw_simple(rd, a);
                next_pc = b.wrapping_add(c) & !1_u64;
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, _) = (imm, imm);
                a = self.state.pc.wrapping_add(b);
                self.rw_simple(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
                // register is that we write to it later.
                let t0 = Register::X5;
                let syscall = SyscallCode::from_rv64(self.register(t0));
                let syscall_id = syscall as u32;
                c = self.rr_simple(Register::X11, MemoryAccessPosition::C);
                b = self.rr_simple(Register::X10, MemoryAccessPosition::B);

                self.mode.check_unconstrained_syscall(syscall)?;

                // Update the syscall counts.
                let syscall_for_count = syscall.count_map();
                let syscall_count = self
                    .state
                    .syscall_counts
                    .entry(syscall_for_count)
                    .or_insert(0);
                if self.log_syscalls {
                    debug!(">>syscall_id: {syscall_id:?}, syscall_count: {syscall_count:?}");
                }
                *syscall_count += 1;

                let syscall_impl = self.get_syscall(syscall).cloned();
                // if syscall.should_send() != 0 {
                //     self.emit_syscall(clk, syscall.syscall_id(), b, c);
                // }
                let mut precompile_rt = SyscallContext::new(self);
                let (precompile_next_pc, precompile_cycles, _returned_exit_code) =
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0
                        // register. If it returns None, we just keep the
                        // syscall_id in t0.
                        let res = syscall_impl.emulate(&mut precompile_rt, syscall, b, c);
                        if let Some(val) = res {
                            a = val;
                        } else {
                            a = u64::from(syscall_id);
                        }

                        // If the syscall is `HALT` and the exit code is non-zero, return an error.
                        if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
                            return Err(EmulationError::HaltWithNonZeroExitCode(
                                precompile_rt.exit_code,
                            ));
                        }

                        (
                            precompile_rt.next_pc,
                            syscall_impl.num_extra_cycles(),
                            precompile_rt.exit_code,
                        )
                    } else {
                        return Err(EmulationError::UnsupportedSyscall(syscall_id));
                    };
                // TODO: this debug syscall somehow improves fibonacci-emulator performance by 10%
                // The reason is unclear.
                // debug!("syscall: {:?}", syscall);
                match syscall {
                    SyscallCode::ENTER_UNCONSTRAINED => self.rw_unconstrained(t0, a),
                    _ => self.rw_simple(t0, a),
                }
                next_pc = precompile_next_pc;
                self.state.clk += u64::from(precompile_cycles);
            }
            Opcode::EBREAK => {
                return Err(EmulationError::Breakpoint());
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = b.wrapping_mul(c);
                self.alu_rw_simple(rd, a);
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = (((b as i64) as i128).wrapping_mul((c as i64) as i128) >> 64) as u64;
                self.alu_rw_simple(rd, a);
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = ((b as u128).wrapping_mul(c as u128) >> 64) as u64;
                self.alu_rw_simple(rd, a);
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                a = (((b as i64) as i128).wrapping_mul(c as i128) >> 64) as u64;
                self.alu_rw_simple(rd, a);
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                if c == 0 {
                    a = u64::MAX;
                } else {
                    a = (b as i64).wrapping_div(c as i64) as u64;
                }
                self.alu_rw_simple(rd, a);
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                if c == 0 {
                    a = u64::MAX;
                } else {
                    a = b / c;
                }
                self.alu_rw_simple(rd, a);
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i64).wrapping_rem(c as i64) as u64;
                }
                self.alu_rw_simple(rd, a);
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr_simple(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.alu_rw_simple(rd, a);
            }
            Opcode::ADDW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = (b as i32).wrapping_add(c as i32) as i64 as u64;
                self.rw_simple(rd, result);
            }
            Opcode::SUBW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = (b as i32).wrapping_sub(c as i32) as i64 as u64;
                self.rw_simple(rd, result);
            }
            Opcode::SLLW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = ((b as u32).wrapping_shl((c & 0x1f) as u32) as i32) as i64 as u64;
                self.rw_simple(rd, result);
            }
            Opcode::SRLW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = (((b as u32) >> ((c & 0x1f) as u32)) as i32) as i64 as u64;
                self.rw_simple(rd, result);
            }
            Opcode::SRAW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = (b as i32).wrapping_shr((c & 0x1f) as u32) as i64 as u64;
                self.rw_simple(rd, result);
            }
            Opcode::MULW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = (b as i32).wrapping_mul(c as i32) as i64 as u64;
                self.rw_simple(rd, result);
            }
            Opcode::DIVW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = if c as i32 == 0 {
                    u64::MAX
                } else {
                    (b as i32).wrapping_div(c as i32) as i64 as u64
                };
                self.rw_simple(rd, result);
            }
            Opcode::DIVUW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = if c as u32 == 0 {
                    u64::MAX
                } else {
                    ((b as u32 / c as u32) as i32) as i64 as u64
                };
                self.rw_simple(rd, result);
            }
            Opcode::REMW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = if c as i32 == 0 {
                    (b as i32) as i64 as u64
                } else {
                    (b as i32).wrapping_rem(c as i32) as i64 as u64
                };
                self.rw_simple(rd, result);
            }
            Opcode::REMUW => {
                (rd, b, c) = self.w_alu_rr_simple(instruction);
                let result = if c as u32 == 0 {
                    (b as i32) as i64 as u64
                } else {
                    ((b as u32 % c as u32) as i32) as i64 as u64
                };
                self.rw_simple(rd, result);
            }

            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/main/src/asm-manual.adoc#instruction-aliases
            Opcode::UNIMP => {
                return Err(EmulationError::Unimplemented());
            }
        }

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        Ok(())
    }
}
