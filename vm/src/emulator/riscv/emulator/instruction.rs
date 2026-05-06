use super::{align_u64, EmulationError, RiscvEmulator};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, register::Register},
    emulator::riscv::syscalls::{syscall_context::SyscallContext, SyscallCode},
};
use tracing::debug;

#[inline(always)]
fn invalid_memory_addr_u64(addr: u64, context: &str) -> u64 {
    let _ = context;
    addr
}

impl RiscvEmulator {
    #[inline(always)]
    fn w_alu_rr(&mut self, instruction: &Instruction) -> (Register, u64, u64) {
        if !instruction.imm_c {
            let (rd, rs1, rs2) = instruction.r_type();
            let c = self.rr(rs2, MemoryAccessPosition::C);
            let b = self.rr(rs1, MemoryAccessPosition::B);
            (rd, b, c)
        } else if !instruction.imm_b {
            let (rd, rs1, imm) = instruction.i_type();
            (rd, self.rr(rs1, MemoryAccessPosition::B), imm)
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
    pub(crate) fn emulate_instruction(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), EmulationError> {
        let mut exit_code = 0u32;
        let mut clk = self.state.clk;
        let mut next_pc = self.state.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u64, u64, u64);
        let (addr, memory_read_value): (u64, u64);
        let mut memory_store_value: Option<u64> = None;
        let mut compat_cpu_event_a_u64: Option<u64> = None;
        let mut compat_cpu_event_b_u64: Option<u64> = None;
        let mut compat_cpu_event_c_u64: Option<u64> = None;

        self.mode.init_memory_access(&mut self.memory_accesses);

        // TODO(rv64im-3r7): remove u64::from ALU payload bridges after canonical ALU operand/result
        // paths are u64 end-to-end (alu_rr/alu result locals no longer u32-compat).
        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.add_events,
                );
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.sub_events,
                );
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.bitwise_events,
                );
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.bitwise_events,
                );
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.bitwise_events,
                );
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shl((c & 0x3f) as u32);
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.shift_left_events,
                );
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shr((c & 0x3f) as u32);
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.shift_right_events,
                );
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i64).wrapping_shr((c & 0x3f) as u32) as u64;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.shift_right_events,
                );
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i64) < (c as i64) { 1 } else { 0 };
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.lt_events,
                );
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.lt_events,
                );
            }

            // Load instructions.
            Opcode::LB => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = memory_read_value.to_le_bytes()[(addr % 8) as usize];
                a = ((value as i8) as i64) as u64;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LH => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LH,
                        invalid_memory_addr_u64(addr, "lh"),
                    ));
                }
                let shift = ((addr / 2) % 4) * 16;
                let value = ((memory_read_value >> shift) & 0xFFFF) as u16;
                a = ((value as i16) as i64) as u64;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LW => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LW,
                        invalid_memory_addr_u64(addr, "lw"),
                    ));
                }
                let shift = ((addr / 4) % 2) * 32;
                let value = ((memory_read_value >> shift) & 0xFFFF_FFFF) as u32;
                a = (value as i32 as i64) as u64;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LBU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = memory_read_value.to_le_bytes()[(addr % 8) as usize];
                a = u64::from(value);
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LHU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LHU,
                        invalid_memory_addr_u64(addr, "lhu"),
                    ));
                }
                let shift = ((addr / 2) % 4) * 16;
                let value = ((memory_read_value >> shift) & 0xFFFF) as u16;
                a = u64::from(value);
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LWU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LWU,
                        invalid_memory_addr_u64(addr, "lwu"),
                    ));
                }
                let shift = ((addr / 4) % 2) * 32;
                a = ((memory_read_value >> shift) & 0xFFFF_FFFF) as u32 as u64;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LD => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if addr % 8 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::LD,
                        invalid_memory_addr_u64(addr, "ld"),
                    ));
                }
                a = memory_read_value;
                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }

            // Store instructions.
            Opcode::SB => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                let shift = (addr % 8) * 8;
                let mask = 0xFFu64 << shift;
                let value = (memory_read_value & !mask) | ((a & 0xFF) << shift);
                memory_store_value = Some(value);
                self.mw_cpu(align_u64(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SD => {
                let (rs1, rs2, imm) = instruction.s_type();
                c = imm;
                b = self.rr(rs2, MemoryAccessPosition::B);
                let store_value = self.rr(rs1, MemoryAccessPosition::A);
                a = store_value;
                addr = b.wrapping_add(c);
                if addr % 8 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::SD,
                        invalid_memory_addr_u64(addr, "sd"),
                    ));
                }
                memory_store_value = Some(store_value);
                self.mw_cpu(align_u64(addr), store_value, MemoryAccessPosition::Memory);
            }
            Opcode::SH => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                if addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::SH,
                        invalid_memory_addr_u64(addr, "sh"),
                    ));
                }
                let shift = ((addr / 2) % 4) * 16;
                let mask = 0xFFFFu64 << shift;
                let value = (memory_read_value & !mask) | ((a & 0xFFFF) << shift);
                memory_store_value = Some(value);
                self.mw_cpu(align_u64(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SW => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                if addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(
                        Opcode::SW,
                        invalid_memory_addr_u64(addr, "sw"),
                    ));
                }
                let shift = ((addr / 4) % 2) * 32;
                let mask = 0xFFFF_FFFFu64 << shift;
                let value = (memory_read_value & !mask) | ((a & 0xFFFF_FFFF) << shift);
                memory_store_value = Some(value);
                self.mw_cpu(align_u64(addr), value, MemoryAccessPosition::Memory);
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
                if (a as i64) < (b as i64) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i64) >= (b as i64) {
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
                a = self.state.pc.wrapping_add(4);
                self.rw(rd, a);
                next_pc = self.state.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
                a = self.state.pc.wrapping_add(4);
                self.rw(rd, a);
                next_pc = b.wrapping_add(c) & !1_u64;
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
                let syscall = SyscallCode::from_rv64(self.register(t0));
                let syscall_id = syscall as u32;
                c = self.rr(Register::X11, MemoryAccessPosition::C);
                b = self.rr(Register::X10, MemoryAccessPosition::B);

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
                if syscall.should_send() != 0 {
                    self.chunk_split_state.record_syscall_event();
                    self.emit_syscall(clk, syscall.syscall_id(), b, c);
                }
                self.chunk_split_state.enter_syscall();
                let syscall_result = (|| {
                    let mut precompile_rt = SyscallContext::new(self);
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0
                        // register. If it returns None, we just keep the
                        // syscall_id in t0.
                        let ret_value = syscall_impl
                            .emulate(&mut precompile_rt, syscall, b, c)
                            .unwrap_or(u64::from(syscall_id));

                        // If the syscall is `HALT` and the exit code is non-zero, return an error.
                        if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
                            return Err(EmulationError::HaltWithNonZeroExitCode(
                                precompile_rt.exit_code,
                            ));
                        }

                        Ok((
                            precompile_rt.next_pc,
                            syscall_impl.num_extra_cycles(),
                            precompile_rt.exit_code,
                            ret_value,
                        ))
                    } else {
                        Err(EmulationError::UnsupportedSyscall(syscall_id))
                    }
                })();
                self.chunk_split_state.exit_syscall();
                let (precompile_next_pc, precompile_cycles, returned_exit_code, ret_value) =
                    syscall_result?;
                a = ret_value;

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                // we must save the clk here because it is modified by precompile_cycles later which
                // means emit_cpu cannot read the correct clk and it must be passed as a value
                clk = self.state.clk;

                self.rw(t0, a);
                next_pc = precompile_next_pc;
                self.state.clk += u64::from(precompile_cycles);
                exit_code = returned_exit_code;
            }
            Opcode::EBREAK => {
                return Err(EmulationError::Breakpoint());
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.mul_events,
                );
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i64) as i128).wrapping_mul((c as i64) as i128) >> 64) as u64;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.mul_events,
                );
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u128).wrapping_mul(c as u128) >> 64) as u64;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.mul_events,
                );
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i64) as i128).wrapping_mul(c as i128) >> 64) as u64;
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.mul_events,
                );
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u64::MAX;
                } else {
                    a = (b as i64).wrapping_div(c as i64) as u64;
                }
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u64::MAX;
                } else {
                    a = b / c;
                }
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i64).wrapping_rem(c as i64) as u64;
                }
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }
                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::ADDW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = (b as i32).wrapping_add(c as i32) as i64 as u64;
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.add_events,
                );
            }
            Opcode::SUBW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = (b as i32).wrapping_sub(c as i32) as i64 as u64;
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.sub_events,
                );
            }
            Opcode::SLLW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = ((b as u32).wrapping_shl((c & 0x1f) as u32) as i32) as i64 as u64;
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.shift_left_events,
                );
            }
            Opcode::SRLW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = (((b as u32) >> ((c & 0x1f) as u32)) as i32) as i64 as u64;
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.shift_right_events,
                );
            }
            Opcode::SRAW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = (b as i32).wrapping_shr((c & 0x1f) as u32) as i64 as u64;
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.shift_right_events,
                );
            }
            Opcode::MULW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = (b as i32).wrapping_mul(c as i32) as i64 as u64;
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.mul_events,
                );
            }
            Opcode::DIVW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = if c as i32 == 0 {
                    u64::MAX
                } else {
                    (b as i32).wrapping_div(c as i32) as i64 as u64
                };
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::DIVUW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = if c as u32 == 0 {
                    u64::MAX
                } else {
                    ((b as u32 / c as u32) as i32) as i64 as u64
                };
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::REMW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = if c as i32 == 0 {
                    (b as i32) as i64 as u64
                } else {
                    (b as i32).wrapping_rem(c as i32) as i64 as u64
                };
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::REMUW => {
                let (rd_tmp, compat_b_u64, compat_c_u64) = self.w_alu_rr(instruction);
                rd = rd_tmp;
                b = compat_b_u64;
                c = compat_c_u64;
                let result = if c as u32 == 0 {
                    (b as i32) as i64 as u64
                } else {
                    ((b as u32 % c as u32) as i32) as i64 as u64
                };
                a = result;
                compat_cpu_event_a_u64 = Some(result);
                compat_cpu_event_b_u64 = Some(compat_b_u64);
                compat_cpu_event_c_u64 = Some(compat_c_u64);
                self.rw(rd, result);
                self.mode.emit_alu(
                    self.state.clk,
                    result,
                    compat_b_u64,
                    compat_c_u64,
                    instruction.opcode,
                    instruction.imm_c,
                    &mut self.record.divrem_events,
                );
            }

            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/main/src/asm-manual.adoc#instruction-aliases
            Opcode::UNIMP => {
                return Err(EmulationError::Unimplemented());
            }
        }

        let compat_cpu_event_a_u64 = compat_cpu_event_a_u64.unwrap_or(a);
        let compat_cpu_event_b_u64 = compat_cpu_event_b_u64.unwrap_or(b);
        let compat_cpu_event_c_u64 = compat_cpu_event_c_u64.unwrap_or(c);

        // Emit the CPU event for this cycle.
        self.mode.emit_cpu(
            self.chunk(),
            clk,
            self.state.pc,
            next_pc,
            exit_code,
            compat_cpu_event_a_u64,
            compat_cpu_event_b_u64,
            compat_cpu_event_c_u64,
            *instruction,
            self.memory_accesses,
            memory_store_value,
            &mut self.record.cpu_events,
            &mut self.record.memory_read_write_event_indices,
        );

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        Ok(())
    }
}
