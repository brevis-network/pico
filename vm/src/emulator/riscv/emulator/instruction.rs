use super::{align, EmulationError, EmulatorMode, RiscvEmulator};

use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, register::Register},
    emulator::riscv::{
        record::MemoryAccessRecord,
        syscalls::{syscall_context::SyscallContext, SyscallCode},
    },
};
use tracing::debug;

impl RiscvEmulator {
    /// Emulate the given instruction over the current state.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn emulate_instruction(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), EmulationError> {
        let mut exit_code = 0u32;
        let mut clk = self.state.clk;
        let mut next_pc = self.state.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u32, u32, u32);
        let (addr, memory_read_value): (u32, u32);
        let mut memory_store_value: Option<u32> = None;

        if self.emulator_mode != EmulatorMode::Simple {
            self.memory_accesses = MemoryAccessRecord::default();
        }

        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shl(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shr(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i32).wrapping_shr(c) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };
                self.alu_rw(instruction, rd, a, b, c);
            }

            // Load instructions.
            Opcode::LB => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = ((value as i8) as i32) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LH => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000_FFFF,
                    1 => (memory_read_value & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                };
                a = ((value as i16) as i32) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LW => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LW, addr));
                }
                a = memory_read_value;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LBU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = value as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LHU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LHU, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000_FFFF,
                    1 => (memory_read_value & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                };
                a = (value as u16) as u32;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }

            // Store instructions.
            Opcode::SB => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                let value = match addr % 4 {
                    0 => (a & 0x0000_00FF) + (memory_read_value & 0xFFFF_FF00),
                    1 => ((a & 0x0000_00FF) << 8) + (memory_read_value & 0xFFFF_00FF),
                    2 => ((a & 0x0000_00FF) << 16) + (memory_read_value & 0xFF00_FFFF),
                    3 => ((a & 0x0000_00FF) << 24) + (memory_read_value & 0x00FF_FFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SH => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => (a & 0x0000_FFFF) + (memory_read_value & 0xFFFF_0000),
                    1 => ((a & 0x0000_FFFF) << 16) + (memory_read_value & 0x0000_FFFF),
                    _ => unreachable!(),
                };
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SW => {
                (a, b, c, addr, _) = self.store_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::SW, addr));
                }
                let value = a;
                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }

            // B-type instructions.
            Opcode::BEQ => {
                (a, b, c) = self.branch_rr(instruction);
                if a == b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                (a, b, c) = self.branch_rr(instruction);
                if a != b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLT => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) < (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) >= (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLTU => {
                (a, b, c) = self.branch_rr(instruction);
                if a < b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGEU => {
                (a, b, c) = self.branch_rr(instruction);
                if a >= b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = self.state.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm);
                a = self.state.pc.wrapping_add(b);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
                // register is that we write to it later.
                let t0 = Register::X5;
                let syscall_id = self.register(t0);
                c = self.rr(Register::X11, MemoryAccessPosition::C);
                b = self.rr(Register::X10, MemoryAccessPosition::B);
                let syscall = SyscallCode::from_u32(syscall_id);
                debug!("emulate syscall code: {:?}", syscall);

                // `hint_slice` is allowed in unconstrained mode since it is used to write the hint.
                // Other syscalls are not allowed because they can lead to non-deterministic
                // behavior, especially since many syscalls modify memory in place,
                // which is not permitted in unconstrained mode. This will result in
                // non-zero memory interactions when generating a proof.
                if self.unconstrained.is_some()
                    && (syscall != SyscallCode::EXIT_UNCONSTRAINED && syscall != SyscallCode::WRITE)
                {
                    return Err(EmulationError::InvalidSyscallUsage(syscall_id as u64));
                }

                // Update the syscall counts.
                let syscall_for_count = syscall.count_map();
                let syscall_count = self
                    .state
                    .syscall_counts
                    .entry(syscall_for_count)
                    .or_insert(0);
                if self.log_syscalls {
                    debug!(
                        ">>syscall_id: {:?}, syscall_count: {:?}",
                        syscall_id, syscall_count,
                    );
                }
                *syscall_count += 1;

                let syscall_impl = self.get_syscall(syscall).cloned();
                if syscall.should_send() != 0 {
                    self.emit_syscall(clk, syscall.syscall_id(), b, c);
                }
                let mut precompile_rt = SyscallContext::new(self);
                let (precompile_next_pc, precompile_cycles, returned_exit_code) =
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0
                        // register. If it returns None, we just keep the
                        // syscall_id in t0.
                        let res = syscall_impl.emulate(&mut precompile_rt, syscall, b, c);
                        if let Some(val) = res {
                            a = val;
                        } else {
                            a = syscall_id;
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

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                // we must save the clk here because it is modified by precompile_cycles later which
                // means emit_cpu cannot read the correct clk and it must be passed as a value
                clk = self.state.clk;

                self.rw(t0, a);
                next_pc = precompile_next_pc;
                self.state.clk += precompile_cycles;
                exit_code = returned_exit_code;
            }
            Opcode::EBREAK => {
                return Err(EmulationError::Breakpoint());
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32;
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = (b as i32).wrapping_div(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = b.wrapping_div(c);
                }
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i32).wrapping_rem(c as i32) as u32;
                }
                self.alu_rw(instruction, rd, a, b, c);
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.alu_rw(instruction, rd, a, b, c);
            }

            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/master/riscv-asm.md#instruction-aliases
            Opcode::UNIMP => {
                return Err(EmulationError::Unimplemented());
            }
        }

        // Emit the CPU event for this cycle.
        if self.emulator_mode == EmulatorMode::Trace {
            self.emit_cpu(
                clk,
                next_pc,
                *instruction,
                a,
                b,
                c,
                memory_store_value,
                self.memory_accesses,
                exit_code,
            );
        };

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        Ok(())
    }
}
