//! Instruction Translation Module for AOT Code Generation
//!
//! This module provides reusable instruction generators that translate RISC-V instructions
//! into Rust code at build time (AOT compilation). The generated code implements the
//! semantics of each instruction type.
//!
//! # Architecture
//!
//! The module is organized around the `InstructionTranslator` struct, which provides
//! methods for generating code for different instruction categories:
//!
//! - **Control Flow**: JAL, JALR, branches (BEQ, BNE, BLT, BGE, BLTU, BGEU)
//! - **ALU Operations**: ADD, SUB, XOR, OR, AND, shifts, comparisons
//! - **Memory Operations**: Load/Store (LB, LH, LW, LBU, LHU, SB, SH, SW)
//! - **Multiply/Divide**: MUL, MULH, MULHU, MULHSU, DIV, DIVU, REM, REMU
//! - **System Calls**: ECALL, UNIMP
//!
//! # Code Generation Strategy
//!
//! Each generator function returns:
//! - `proc_macro2::TokenStream`: The generated Rust code
//! - `bool`: Whether the instruction terminates the basic block
//!
//! Terminal instructions (control flow, syscalls) return `true` and include their own
//! clock updates. Non-terminal instructions return `false` and batch clock updates
//! at the superblock level for performance.

use crate::types::{Instruction, Opcode};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashSet;

/// Instruction translator for AOT code generation.
///
/// This struct provides methods to translate RISC-V instructions into optimized
/// Rust code that can be compiled ahead-of-time. The generated code is designed
/// for maximum performance through inlining and specialized handling of each
/// instruction type.
///
/// # Example
///
/// ```ignore
/// let translator = InstructionTranslator::new(true);
/// let (code, is_terminal, mem_rw_events) = translator.translate(pc, &instruction, &leaders);
/// ```
pub struct InstructionTranslator {
    allow_direct_jumps: bool,
}

impl InstructionTranslator {
    /// Creates a new instruction translator.
    pub fn new(allow_direct_jumps: bool) -> Self {
        Self { allow_direct_jumps }
    }

    /// Translates a RISC-V instruction into Rust code.
    ///
    /// # Parameters
    ///
    /// - `pc`: Program counter for the instruction
    /// - `inst`: The instruction to translate
    /// - `leaders`: Set of basic block leader addresses (for optimizing branches)
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `TokenStream`: The generated Rust code
    /// - `bool`: Whether this instruction terminates the basic block
    /// - `usize`: Static memory RW event count contributed by this instruction
    pub fn translate(
        &self,
        pc: u32,
        inst: &Instruction,
        leaders: &HashSet<u32>,
    ) -> (TokenStream, bool, usize) {
        match inst.opcode {
            // Control Flow
            Opcode::JAL => self.gen_jal(pc, inst, leaders),
            Opcode::JALR => self.gen_jalr(pc, inst),
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.gen_branch(pc, inst, leaders)
            }
            Opcode::ECALL => self.gen_ecall(pc, inst),
            Opcode::EBREAK => self.gen_ebreak(pc),
            Opcode::UNIMP => self.gen_unimp(pc, inst),

            // Normal Instructions (Updates state, returns false)
            _ => self.gen_normal_instruction(pc, inst),
        }
    }

    /// Generates code for non-control-flow instructions.
    fn gen_normal_instruction(&self, pc: u32, inst: &Instruction) -> (TokenStream, bool, usize) {
        match inst.opcode {
            Opcode::ADD => (self.gen_alu_helper(pc, inst, "adi", "adr"), false, 1),
            Opcode::SUB => (self.gen_alu_helper(pc, inst, "sbi", "sbr"), false, 1),
            Opcode::XOR => (self.gen_alu_helper(pc, inst, "xri", "xrr"), false, 1),
            Opcode::OR => (self.gen_alu_helper(pc, inst, "ori", "orr"), false, 1),
            Opcode::AND => (self.gen_alu_helper(pc, inst, "ani", "anr"), false, 1),
            Opcode::SLL => (self.gen_alu_helper(pc, inst, "sli", "slr"), false, 1),
            Opcode::SRL => (self.gen_alu_helper(pc, inst, "sri", "srr"), false, 1),
            Opcode::SRA => (self.gen_alu_helper(pc, inst, "sai", "sar"), false, 1),
            Opcode::SLT => (self.gen_alu_helper(pc, inst, "slti", "sltr"), false, 1),
            Opcode::SLTU => (self.gen_alu_helper(pc, inst, "sltiu", "sltru"), false, 1),
            Opcode::AUIPC => (self.gen_auipc(pc, inst), false, 1),
            Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU => {
                (self.gen_load(pc, inst), false, 1)
            }
            Opcode::SB | Opcode::SH | Opcode::SW => (self.gen_store(pc, inst), false, 1),
            Opcode::MUL => (self.gen_rr_helper(pc, inst, "mul"), false, 1),
            Opcode::MULH => (self.gen_rr_helper(pc, inst, "mulh"), false, 1),
            Opcode::MULHU => (self.gen_rr_helper(pc, inst, "mulhu"), false, 1),
            Opcode::MULHSU => (self.gen_rr_helper(pc, inst, "mulhsu"), false, 1),
            Opcode::DIV => (self.gen_rr_helper(pc, inst, "div"), false, 1),
            Opcode::DIVU => (self.gen_rr_helper(pc, inst, "divu"), false, 1),
            Opcode::REM => (self.gen_rr_helper(pc, inst, "rem"), false, 1),
            Opcode::REMU => (self.gen_rr_helper(pc, inst, "remu"), false, 1),
            _ => {
                panic!(
                    "AOT build error: Unknown or unsupported opcode {:?} at PC {:#x}. \
                     This opcode is not yet implemented in the AOT code generator.",
                    inst.opcode, pc
                );
            }
        }
    }

    // --- Control Flow Generators (Terminators) ---

    /// Generates code for JAL (Jump and Link) instruction.
    ///
    /// JAL performs an unconditional jump and stores the return address.
    /// The generated code optimizes direct jumps to known block leaders.
    fn gen_jal(
        &self,
        pc: u32,
        inst: &Instruction,
        leaders: &HashSet<u32>,
    ) -> (TokenStream, bool, usize) {
        let (rd, imm) = inst.j_type();
        let rd = rd as usize;
        let next_pc = pc.wrapping_add(4);
        let target = pc.wrapping_add(imm);

        let next_step = if self.allow_direct_jumps && leaders.contains(&target) {
            let target_block = format_ident!("block_0x{:08x}", target);
            quote! { crate::NextStep::Direct(#target_block) }
        } else {
            quote! { crate::NextStep::Dynamic(#target) }
        };

        let code = quote! {
            let return_addr = #next_pc;
            emu.write_reg_no_count(#rd, return_addr);
            emu.pc = #target;
            emu.update_insn_clock();
            emu.check_chunk_boundary_fast();
            if emu.should_yield() {
                return Ok(crate::NextStep::Dynamic(emu.pc));
            }
            return Ok(#next_step);
        };
        (code, true, 1)
    }

    /// Generates code for JALR (Jump and Link Register) instruction.
    ///
    /// JALR performs an indirect jump through a register value.
    /// Always returns Dynamic step since the target is computed at runtime.
    fn gen_jalr(&self, pc: u32, inst: &Instruction) -> (TokenStream, bool, usize) {
        let (rd, rs1, imm) = inst.i_type();
        let rd = rd as usize;
        let rs1 = rs1 as usize;
        let next_pc = pc.wrapping_add(4);

        let code = quote! {
            let base = emu.read_reg_b_tracked(#rs1);
            let return_addr = #next_pc;
            emu.write_reg_no_count(#rd, return_addr);
            let target = base.wrapping_add(#imm);
            emu.pc = target;
            emu.update_insn_clock();
            emu.check_chunk_boundary_fast();
            if emu.should_yield() {
                return Ok(crate::NextStep::Dynamic(emu.pc));
            }
            return Ok(crate::NextStep::Dynamic(target));
        };
        (code, true, 1)
    }

    /// Generates code for branch instructions (BEQ, BNE, BLT, BGE, BLTU, BGEU).
    ///
    /// Branches compare two registers and conditionally jump. The generated code
    /// optimizes both branch target and fallthrough paths when they are known
    /// block leaders.
    fn gen_branch(
        &self,
        pc: u32,
        inst: &Instruction,
        leaders: &HashSet<u32>,
    ) -> (TokenStream, bool, usize) {
        let (rs1, rs2, imm) = inst.b_type();
        let rs1 = rs1 as usize;
        let rs2 = rs2 as usize;
        let target = pc.wrapping_add(imm);
        let fallthrough = pc.wrapping_add(4);

        let cond = match inst.opcode {
            Opcode::BEQ => quote! { a == b },
            Opcode::BNE => quote! { a != b },
            Opcode::BLT => quote! { (a as i32) < (b as i32) },
            Opcode::BGE => quote! { (a as i32) >= (b as i32) },
            Opcode::BLTU => quote! { a < b },
            Opcode::BGEU => quote! { a >= b },
            _ => quote! { false },
        };

        let target_step = if self.allow_direct_jumps && leaders.contains(&target) {
            let name = format_ident!("block_0x{:08x}", target);
            quote! { crate::NextStep::Direct(#name) }
        } else {
            quote! { crate::NextStep::Dynamic(#target) }
        };

        let fallthrough_step = if self.allow_direct_jumps && leaders.contains(&fallthrough) {
            let name = format_ident!("block_0x{:08x}", fallthrough);
            quote! { crate::NextStep::Direct(#name) }
        } else {
            quote! { crate::NextStep::Dynamic(#fallthrough) }
        };

        let code = quote! {
            let b = emu.read_reg_b_tracked(#rs2);
            let a = emu.read_reg_a_tracked(#rs1);
            if #cond {
                emu.pc = #target;
                emu.update_insn_clock();
                emu.check_chunk_boundary_fast();
                if emu.should_yield() {
                return Ok(crate::NextStep::Dynamic(emu.pc));
            }
                return Ok(#target_step);
            } else {
                emu.pc = #fallthrough;
                emu.update_insn_clock();
                emu.check_chunk_boundary_fast();
                if emu.should_yield() {
                    return Ok(crate::NextStep::Dynamic(emu.pc));
                }
                return Ok(#fallthrough_step);
            }
        };
        (code, true, 0)
    }

    /// Generates code for ECALL (Environment Call) instruction.
    ///
    /// ECALL invokes system calls. The generated code delegates to the
    /// emulator's generic syscall system and handles return values, extra
    /// cycles, and potential halts.
    fn gen_ecall(&self, _pc: u32, _inst: &Instruction) -> (TokenStream, bool, usize) {
        let code = quote! {
            // Read the full 32-bit syscall number from t0 (x5)
            // SyscallCode encodes: [ID, Table, Cycles, Unused] in little-endian
            let syscall_id = emu.read_reg_snapshot(5);
            let arg2 = emu.read_reg_c(11); // a1 (x11)
            let arg1 = emu.read_reg_b(10); // a0 (x10)

            // Execute syscall via the generic syscall system
            match emu.execute_syscall(syscall_id, arg1, arg2) {
                Ok((return_value, new_next_pc, extra_cycles, should_halt)) => {
                    // Write return value to t0 (x5)
                    emu.write_reg_no_count(5, return_value);

                    // Update PC and clock
                    // Note: new_next_pc is usually pc+4, but some syscalls like
                    // EXIT_UNCONSTRAINED restore a different PC
                    emu.pc = new_next_pc;
                    emu.update_insn_clock();

                    // Handle extra cycles from complex precompiles
                    // Note: extra_cycles only affects clk (for chunk boundary), NOT insn_count
                    // This matches baseline behavior where precompile_cycles only adds to clk
                    if extra_cycles > 0 {
                        emu.clk = emu.clk.wrapping_add(extra_cycles);
                    }

                    // Check for halt
                    if should_halt {
                        emu.check_chunk_boundary_fast();
                        return Ok(crate::NextStep::Halt);
                    }

                    // Check chunk boundary and yield
                    emu.check_chunk_boundary_fast();

                    // Continue execution using emu.pc (which was set to new_next_pc)
                    // This is important for syscalls that modify the PC like EXIT_UNCONSTRAINED
                    return Ok(crate::NextStep::Dynamic(emu.pc));
                }
                Err(e) => {
                    return Err(e);
                }
            }
        };
        (code, true, 1)
    }

    /// Generates code for EBREAK (breakpoint) instruction.
    fn gen_ebreak(&self, pc: u32) -> (TokenStream, bool, usize) {
        let code = quote! {
            return Err(format!("Breakpoint at PC {:#x}", #pc));
        };
        (code, true, 0)
    }

    /// Generates code for UNIMP (Unimplemented) instruction.
    ///
    /// UNIMP is a pseudo-instruction that should always error.
    fn gen_unimp(&self, pc: u32, _inst: &Instruction) -> (TokenStream, bool, usize) {
        let code = quote! {
            emu.update_insn_clock();
            return Err(format!("Unimplemented instruction (UNIMP) at PC {:#x}", #pc));
        };
        (code, true, 0)
    }

    // --- ALU Generators (Non-Terminators) ---

    /// Generates code that dispatches to AOT runtime helpers for ALU ops.
    fn gen_alu_helper(
        &self,
        pc: u32,
        inst: &Instruction,
        imm_helper: &str,
        reg_helper: &str,
    ) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        if inst.imm_b && inst.imm_c {
            let rd = inst.op_a as usize;
            let b = inst.op_b;
            let c = inst.op_c;
            let op = match inst.opcode {
                Opcode::ADD => quote! { let a = #b.wrapping_add(#c); },
                Opcode::SUB => quote! { let a = #b.wrapping_sub(#c); },
                Opcode::XOR => quote! { let a = #b ^ #c; },
                Opcode::OR => quote! { let a = #b | #c; },
                Opcode::AND => quote! { let a = #b & #c; },
                Opcode::SLL => quote! { let a = #b.wrapping_shl(#c & 0x1f); },
                Opcode::SRL => quote! { let a = #b.wrapping_shr(#c & 0x1f); },
                Opcode::SRA => quote! { let a = ((#b as i32).wrapping_shr(#c & 0x1f)) as u32; },
                Opcode::SLT => quote! { let a = if (#b as i32) < (#c as i32) { 1 } else { 0 }; },
                Opcode::SLTU => quote! { let a = if #b < #c { 1 } else { 0 }; },
                _ => quote! { unreachable!() },
            };

            quote! {
                #op
                emu.write_reg_no_count(#rd, a);
                emu.pc = #next_pc;
                emu.update_insn_clock();
            }
        } else {
            let (rd, rs1, rs2, imm, use_imm) = decode_rr_imm(inst);
            let imm_helper_tracked = format_ident!("{}_no_count", imm_helper);
            let reg_helper_tracked = format_ident!("{}_no_count", reg_helper);

            if use_imm {
                quote! {
                    emu.#imm_helper_tracked(#rd, #rs1, #imm, #next_pc);
                }
            } else {
                quote! {
                    emu.#reg_helper_tracked(#rd, #rs1, #rs2, #next_pc);
                }
            }
        }
    }

    /// Generates code for register-register operations (R-type only).
    fn gen_rr_helper(&self, pc: u32, inst: &Instruction, helper: &str) -> TokenStream {
        let (rd, rs1, rs2) = inst.r_type();
        let rd = rd as usize;
        let rs1 = rs1 as usize;
        let rs2 = rs2 as usize;
        let next_pc = pc.wrapping_add(4);
        let helper = format_ident!("{}_no_count", helper);

        quote! {
            emu.#helper(#rd, #rs1, #rs2, #next_pc);
        }
    }

    /// Generates code for AUIPC (Add Upper Immediate to PC) instruction.
    fn gen_auipc(&self, pc: u32, inst: &Instruction) -> TokenStream {
        let (rd, imm) = inst.u_type();
        let rd = rd as usize;
        let next_pc = pc.wrapping_add(4);

        quote! {
            emu.apc_no_count(#rd, #pc, #imm, #next_pc);
        }
    }

    // --- Memory Generators ---

    /// Generates code for load instructions (LB, LH, LW, LBU, LHU).
    ///
    /// Handles byte, halfword, and word loads with proper sign/zero extension.
    fn gen_load(&self, pc: u32, inst: &Instruction) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        let (rd, rs1, imm) = inst.i_type();
        let rd = rd as usize;
        let rs1 = rs1 as usize;

        match inst.opcode {
            Opcode::LB => quote! {
                emu.lb_no_count(#rd, #rs1, #imm, #next_pc);
            },
            Opcode::LH => quote! {
                emu.lh_no_count(#rd, #rs1, #imm, #next_pc)?;
            },
            Opcode::LW => quote! {
                emu.lw_no_count(#rd, #rs1, #imm, #next_pc)?;
            },
            Opcode::LBU => quote! {
                emu.lbu_no_count(#rd, #rs1, #imm, #next_pc);
            },
            Opcode::LHU => quote! {
                emu.lhu_no_count(#rd, #rs1, #imm, #next_pc)?;
            },
            _ => quote! { unreachable!() },
        }
    }

    /// Generates code for store instructions (SB, SH, SW).
    ///
    /// Handles byte, halfword, and word stores with proper masking.
    fn gen_store(&self, pc: u32, inst: &Instruction) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        // NOTE: Pico's custom instruction encoding stores S-type as:
        // op_a = rs2 (value), op_b = rs1 (base), op_c = imm.
        let (rs2, rs1, imm) = inst.s_type();
        let rs1 = rs1 as usize; // base register
        let rs2 = rs2 as usize; // value register

        match inst.opcode {
            Opcode::SB => quote! {
                emu.sb_no_count(#rs2, #rs1, #imm, #next_pc);
            },
            Opcode::SH => quote! {
                emu.sh_no_count(#rs2, #rs1, #imm, #next_pc)?;
            },
            Opcode::SW => quote! {
                emu.sw_no_count(#rs2, #rs1, #imm, #next_pc)?;
            },
            _ => quote! { unreachable!() },
        }
    }
}

impl Default for InstructionTranslator {
    fn default() -> Self {
        Self::new(true)
    }
}

// --- Helper Functions ---

/// Decodes register-register or register-immediate instruction operands.
///
/// Returns: (rd, rs1, rs2, imm, use_imm)
fn decode_rr_imm(inst: &Instruction) -> (usize, usize, usize, u32, bool) {
    if !inst.imm_c {
        // R-type
        let (rd, rs1, rs2) = inst.r_type();
        (rd as usize, rs1 as usize, rs2 as usize, 0, false)
    } else {
        // I-type
        let (rd, rs1, imm) = inst.i_type();
        (rd as usize, rs1 as usize, 0, imm, true)
    }
}
