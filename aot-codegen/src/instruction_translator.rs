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
//! - `usize`: Exact static memory RW event count
//! - `usize`: Conservative static global lookup base contribution
//!
//! Terminal instructions (control flow, syscalls) return `true` and include their own clock
//! updates. Non-terminal instructions return `false`; their runtime helpers update the clock.
//!
//! # Events
//!
//! Every instruction but `ECALL` runs through a runtime helper, which writes its events when the
//! core emits any. A block reads whether it does once, on entry, into `emitting`, and hands that
//! to every helper: the sink cannot change while a block runs, and one flag tested by every helper
//! is what lets the compiler run the block's plain bodies back to back, with no test between them.
//! A jump or a branch leaves only the pc, the clock and the block's exit to the code here.
//! `ECALL` ends its instruction through the core, which tests the sink itself.
//!
//! # Recording bodies
//!
//! Every block also gets a recording body ([`BlockBody::Recorder`]), which only a replay worker
//! runs: the same instructions writing the same rows, into the sink the recorder holds for the
//! whole dispatch run, and stepping only to recording bodies.
//!
//! Every instruction that writes a row but `ECALL` is one call of a direct runtime entry
//! ([`writes_rows_directly`]), handed the program's instruction as constants. An ALU instruction,
//! `AUIPC` or load writing `x0` is the only kind whose operand the history's rule can miss, so only
//! its entry checks for an operand exception ([`x0_can_miss_its_a`]). As with the helpers, a jump
//! leaves the pc, the clock and the block's exit to the code here. A branch or `JAL` whose target
//! no row holds (rows hold pcs as `u32`) runs its helper's emitting `_rec` entry instead, and
//! taking it fails the jump check before any cut, as in the interpreter's run. `ECALL` runs the
//! plain body's sequence with the sink back on the core (`with_sink_on_core`).
//!
//! A recording body keeps no chunk-split tally and tests no chunk boundary: it runs only on a
//! replay worker, whose split is off (`ChunkSplitConfig::disabled`), so nothing reads the tally and
//! no test could cut.
//!
//! # Operands
//!
//! Both bodies, and the helpers they call, take every constant from the program's own instruction
//! as `pico-vm` holds it: an immediate is its `u64`, never narrowed. Only a register operand is
//! narrowed, to an index, and checked to name one of `x0` to `x31` (`register`).

use crate::types::{Instruction, Opcode, ProgramInfo};
use pico_vm::emulator::riscv::{history::Slots, record::AluStream, sink::BlockRows};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashSet;

/// Whether a recording body writes the rows of `inst`, at `pc`, directly: every instruction but
/// `ECALL`, `EBREAK` and `UNIMP`, unless it is a branch or `JAL` whose target no row holds.
pub fn writes_rows_directly(pc: u64, inst: &Instruction) -> bool {
    let to_a_row = |offset: u64| u32::try_from(pc.wrapping_add(offset)).is_ok();
    if inst.is_branch_instruction() {
        return to_a_row(inst.op_c);
    }
    match inst.opcode {
        Opcode::JAL => to_a_row(inst.op_b),
        Opcode::AUIPC | Opcode::JALR => true,
        _ => inst.is_alu_instruction() || inst.is_memory_instruction(),
    }
}

/// Whether `inst`'s `a` is a value it computes or loads (an ALU instruction, `AUIPC` or a load),
/// which an `x0` destination does not hold, so the history's operand rule can miss it.
pub fn x0_can_miss_its_a(inst: &Instruction) -> bool {
    inst.is_alu_instruction() || inst.opcode == Opcode::AUIPC || is_load(inst)
}

fn is_load(inst: &Instruction) -> bool {
    matches!(
        inst.opcode,
        Opcode::LB | Opcode::LH | Opcode::LW | Opcode::LBU | Opcode::LHU | Opcode::LWU | Opcode::LD
    )
}

/// Adds to `room` the rows `inst`, one [`writes_rows_directly`] takes, writes directly.
pub fn add_direct_rows(room: &mut BlockRows, inst: &Instruction) {
    let slots = Slots::of(inst);
    room.steps += 1;
    room.reads += slots.len() - slots.write_count();
    room.writes += slots.write_count();
    let x0 = inst.op_a == 0;
    if x0 && x0_can_miss_its_a(inst) {
        room.operand_exceptions += 1;
    }
    if inst.is_alu_instruction() && !x0 {
        *room.alu_mut(AluStream::of(inst.opcode)) += 1;
    }
    if inst.is_memory_instruction() {
        room.memory += 1;
    } else if inst.is_branch_instruction() {
        room.branch += 1;
    }
}

/// The call of `inst`'s direct entry, `None` for one [`writes_rows_directly`] leaves to its
/// helper.
fn direct_call(pc: u64, inst: &Instruction) -> Option<TokenStream> {
    if !writes_rows_directly(pc, inst) {
        return None;
    }
    // The history stores pcs as u32, and a step's next pc can be this one's plus 4.
    let row_pc = u32::try_from(pc)
        .ok()
        .filter(|pc| pc.checked_add(4).is_some())
        .unwrap_or_else(|| {
            panic!(
                "AOT build error: a recording body writes pcs as u32, and {pc:#x} + 4 is not one"
            )
        });
    let opcode = format_ident!("{}", format!("{:?}", inst.opcode));
    let Instruction {
        op_a,
        op_b,
        op_c,
        imm_b,
        imm_c,
        ..
    } = *inst;
    let insn = quote! { Instruction::new(Opcode::#opcode, #op_a, #op_b, #op_c, #imm_b, #imm_c) };
    let x0 = op_a == 0 && x0_can_miss_its_a(inst);
    Some(match inst.opcode {
        Opcode::AUIPC if x0 => quote! { emu.auipc_x0_direct_rec(rec, #row_pc, #insn) },
        Opcode::AUIPC => quote! { emu.auipc_direct_rec(rec, #row_pc, #insn) },
        _ if inst.is_alu_instruction() && x0 => {
            quote! { emu.alu_x0_direct_rec(rec, #row_pc, #insn) }
        }
        opcode if inst.is_alu_instruction() => {
            let stream = format_ident!("{}", format!("{:?}", AluStream::of(opcode)));
            quote! { emu.alu_direct_rec(rec, #row_pc, #insn, AluStream::#stream) }
        }
        _ if is_load(inst) && x0 => quote! { emu.load_x0_direct_rec(rec, #row_pc, #insn)? },
        _ if is_load(inst) => quote! { emu.load_direct_rec(rec, #row_pc, #insn)? },
        _ if inst.is_memory_instruction() => {
            quote! { emu.store_direct_rec(rec, #row_pc, #insn)? }
        }
        _ if inst.is_branch_instruction() => {
            quote! { emu.branch_direct_rec(rec, #row_pc, #insn) }
        }
        Opcode::JAL => quote! { emu.jal_direct_rec(rec, #row_pc, #insn) },
        Opcode::JALR => quote! { emu.jalr_direct_rec(rec, #row_pc, #insn)? },
        other => unreachable!("{other:?} at {pc:#x} is not written directly"),
    })
}

/// Which body of a block the translator writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockBody {
    /// `block_0x{pc}`, which every core runs: the helpers take the block's `emitting`.
    Plain,
    /// `rec_block_0x{pc}`, which a replay worker runs: the helpers' `_rec` entries take the
    /// block's `rec`.
    Recorder,
}

impl BlockBody {
    /// The function holding this body of the block at `pc`.
    pub fn block_name(self, pc: u64) -> proc_macro2::Ident {
        match self {
            Self::Plain => format_ident!("block_0x{:08x}", pc),
            Self::Recorder => format_ident!("rec_block_0x{:08x}", pc),
        }
    }

    /// The step a block of this body returns.
    pub fn step(self) -> TokenStream {
        match self {
            Self::Plain => quote! { crate::NextStep },
            Self::Recorder => quote! { crate::RecordStep },
        }
    }

    /// The call of `helper`'s entry for this body, with the argument that selects its sink.
    fn helper(self, helper: &str) -> (proc_macro2::Ident, TokenStream) {
        match self {
            Self::Plain => (format_ident!("{}_no_count", helper), quote! { emitting }),
            Self::Recorder => (format_ident!("{}_rec", helper), quote! { rec }),
        }
    }

    /// The chunk-boundary check at a block's exit; none in a recording body (the module header).
    pub fn check_chunk_boundary(self) -> TokenStream {
        match self {
            Self::Plain => quote! { emu.check_chunk_boundary_fast(); },
            Self::Recorder => quote! {},
        }
    }
}

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
/// let translator = InstructionTranslator::new();
/// let (code, is_terminal, mem_rw_events, global_lookup_base) =
///     translator.translate(pc, &instruction, &leaders);
/// ```
#[derive(Default)]
pub struct InstructionTranslator {
    /// The program's instruction addresses, `[pc_base, pc_base + 4 * len)`, when known: a
    /// statically known jump or branch target inside them needs no check at run time.
    code: Option<core::ops::Range<u64>>,
}

impl InstructionTranslator {
    /// Creates a new instruction translator that does not know the program's extent: every jump
    /// and taken branch is checked at run time.
    pub fn new() -> Self {
        Self { code: None }
    }

    /// A translator for `program`, which checks a statically known target at generation time.
    pub fn for_program(program: &ProgramInfo) -> Self {
        let end = program.pc_base + 4 * program.instructions.len() as u64;
        Self {
            code: Some(program.pc_base..end),
        }
    }

    /// The check for a jump or taken branch at `pc` to the statically known `target`: nothing when
    /// it is one of the program's instructions, else the run-time check, which then fails as the
    /// interpreter's does (`AotEmulatorCore::check_jump_target`).
    fn static_jump_check(&self, pc: u64, target: u64) -> TokenStream {
        let valid = target.is_multiple_of(4)
            && self
                .code
                .as_ref()
                .is_some_and(|code| code.contains(&target));
        if valid {
            quote! {}
        } else {
            quote! { emu.check_jump_target(#pc, #target)?; }
        }
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
    /// - `usize`: Conservative static global lookup base contribution
    pub fn translate(
        &self,
        pc: u64,
        inst: &Instruction,
        leaders: &HashSet<u64>,
    ) -> (TokenStream, bool, usize, usize) {
        self.translate_body(BlockBody::Plain, pc, inst, leaders)
    }

    /// [`Self::translate`] into `body`; the counts do not depend on it.
    pub fn translate_body(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        leaders: &HashSet<u64>,
    ) -> (TokenStream, bool, usize, usize) {
        let direct = match body {
            BlockBody::Plain => None,
            BlockBody::Recorder => direct_call(pc, inst),
        };
        match inst.opcode {
            // Control Flow
            Opcode::JAL => self.gen_jal(body, pc, inst, direct, leaders),
            Opcode::JALR => self.gen_jalr(body, pc, inst, direct),
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                self.gen_branch(body, pc, inst, direct, leaders)
            }
            Opcode::ECALL => self.gen_ecall(body, pc, inst),
            Opcode::EBREAK => self.gen_ebreak(pc),
            Opcode::UNIMP => self.gen_unimp(pc, inst),

            // Normal Instructions (Updates state, returns false)
            _ => {
                let (code, is_terminal, mem_rw_events, global_lookup_base) =
                    self.gen_normal_instruction(body, pc, inst);
                let code = direct.map_or(code, |call| quote! { #call; });
                (code, is_terminal, mem_rw_events, global_lookup_base)
            }
        }
    }

    /// Generates code for non-control-flow instructions.
    fn gen_normal_instruction(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
    ) -> (TokenStream, bool, usize, usize) {
        let alu =
            |imm_helper, reg_helper| self.gen_alu_helper(body, pc, inst, imm_helper, reg_helper);
        let rr = |helper| self.gen_rr_helper(body, pc, inst, helper);
        let word = |helper| self.gen_word_alu_helper(body, pc, inst, helper);
        match inst.opcode {
            Opcode::ADD => (alu("adi", "adr"), false, 1, 1),
            Opcode::SUB => (alu("sbi", "sbr"), false, 1, 1),
            Opcode::XOR => (alu("xri", "xrr"), false, 1, 1),
            Opcode::OR => (alu("ori", "orr"), false, 1, 1),
            Opcode::AND => (alu("ani", "anr"), false, 1, 1),
            Opcode::SLL => (alu("sli", "slr"), false, 1, 1),
            Opcode::SRL => (alu("sri", "srr"), false, 1, 1),
            Opcode::SRA => (alu("sai", "sar"), false, 1, 1),
            Opcode::SLT => (alu("slti", "sltr"), false, 1, 1),
            Opcode::SLTU => (alu("sltiu", "sltru"), false, 1, 1),
            Opcode::AUIPC => (self.gen_auipc(body, pc, inst), false, 1, 1),
            Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::LWU
            | Opcode::LD => (self.gen_load(body, pc, inst), false, 1, 2),
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                (self.gen_store(body, pc, inst), false, 1, 1)
            }
            Opcode::MUL => (rr("mul"), false, 1, 1),
            Opcode::MULH => (rr("mulh"), false, 1, 1),
            Opcode::MULHU => (rr("mulhu"), false, 1, 1),
            Opcode::MULHSU => (rr("mulhsu"), false, 1, 1),
            Opcode::DIV => (rr("div"), false, 1, 1),
            Opcode::DIVU => (rr("divu"), false, 1, 1),
            Opcode::REM => (rr("rem"), false, 1, 1),
            Opcode::REMU => (rr("remu"), false, 1, 1),
            Opcode::ADDW => (word("addw"), false, 1, 1),
            Opcode::SUBW => (rr("subw"), false, 1, 1),
            Opcode::SLLW => (word("sllw"), false, 1, 1),
            Opcode::SRLW => (word("srlw"), false, 1, 1),
            Opcode::SRAW => (word("sraw"), false, 1, 1),
            Opcode::MULW => (rr("mulw"), false, 1, 1),
            Opcode::DIVW => (rr("divw"), false, 1, 1),
            Opcode::DIVUW => (rr("divuw"), false, 1, 1),
            Opcode::REMW => (rr("remw"), false, 1, 1),
            Opcode::REMUW => (rr("remuw"), false, 1, 1),
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

    /// The step to `target`: straight to its block's `body` where a block starts there, else by pc.
    fn step_to(body: BlockBody, target: u64, leaders: &HashSet<u64>) -> TokenStream {
        let step = body.step();
        if leaders.contains(&target) {
            let target_block = body.block_name(target);
            quote! { #step::Direct(#target_block) }
        } else {
            quote! { #step::Dynamic(#target) }
        }
    }

    /// Generates code for JAL (Jump and Link) instruction.
    ///
    /// JAL performs an unconditional jump and stores the return address.
    /// The generated code optimizes direct jumps to known block leaders. `direct`, in a recording
    /// body, writes the link and its rows in place of the helper.
    fn gen_jal(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        direct: Option<TokenStream>,
        leaders: &HashSet<u64>,
    ) -> (TokenStream, bool, usize, usize) {
        let (rd, imm) = (register(inst.op_a), inst.op_b);
        let target = pc.wrapping_add(imm);

        let next_step = Self::step_to(body, target, leaders);
        let link = direct.unwrap_or_else(|| {
            let (helper, sink) = body.helper("jal");
            quote! { emu.#helper(#sink, #rd, #pc, #imm) }
        });
        let (step, check) = (body.step(), body.check_chunk_boundary());
        let jump_check = self.static_jump_check(pc, target);
        let code = quote! {
            #jump_check
            #link;
            emu.pc = #target;
            emu.update_insn_clock();
            #check
            if emu.should_yield() {
                return Ok(#step::Dynamic(emu.pc));
            }
            Ok(#next_step)
        };
        (code, true, 1, 1)
    }

    /// Generates code for JALR (Jump and Link Register) instruction.
    ///
    /// JALR performs an indirect jump through a register value.
    /// Always returns Dynamic step since the target is computed at runtime. Its target is known
    /// only once the register is read, so its entry checks it, before it writes the link, as the
    /// interpreter does, and the code here hands the error on. `direct`, in a recording body,
    /// writes the link and its rows and returns the target in place of the helper.
    fn gen_jalr(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        direct: Option<TokenStream>,
    ) -> (TokenStream, bool, usize, usize) {
        let (rd, rs1, imm) = (register(inst.op_a), register(inst.op_b), inst.op_c);

        let jump = direct.unwrap_or_else(|| {
            assert_eq!(
                body,
                BlockBody::Plain,
                "a recording body writes every JALR directly"
            );
            quote! { emu.jalr_no_count(emitting, #rd, #rs1, #pc, #imm)? }
        });
        let (step, check) = (body.step(), body.check_chunk_boundary());
        let code = quote! {
            let target = #jump;
            emu.pc = target;
            emu.update_insn_clock();
            #check
            if emu.should_yield() {
                return Ok(#step::Dynamic(emu.pc));
            }
            Ok(#step::Dynamic(target))
        };
        (code, true, 1, 1)
    }

    /// Generates code for branch instructions (BEQ, BNE, BLT, BGE, BLTU, BGEU).
    ///
    /// Branches compare two registers and conditionally jump. The generated code
    /// optimizes both branch target and fallthrough paths when they are known
    /// block leaders. `direct`, in a recording body, writes the branch's rows and decides it in
    /// place of the helper.
    fn gen_branch(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        direct: Option<TokenStream>,
        leaders: &HashSet<u64>,
    ) -> (TokenStream, bool, usize, usize) {
        let (rs1, rs2, imm) = (register(inst.op_a), register(inst.op_b), inst.op_c);
        let target = pc.wrapping_add(imm);
        let fallthrough = pc.wrapping_add(4);

        let helper = match inst.opcode {
            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BLT => "blt",
            Opcode::BGE => "bge",
            Opcode::BLTU => "bltu",
            Opcode::BGEU => "bgeu",
            other => unreachable!("{other:?} at PC {pc:#x} is not a branch"),
        };
        let decide = direct.unwrap_or_else(|| {
            let (helper, sink) = body.helper(helper);
            quote! { emu.#helper(#sink, #rs1, #rs2, #pc, #imm) }
        });

        let target_step = Self::step_to(body, target, leaders);
        let fallthrough_step = Self::step_to(body, fallthrough, leaders);

        let (step, check) = (body.step(), body.check_chunk_boundary());
        let jump_check = self.static_jump_check(pc, target);
        let code = quote! {
            let taken = #decide;
            if taken {
                #jump_check
                emu.pc = #target;
                emu.update_insn_clock();
                #check
                if emu.should_yield() {
                    return Ok(#step::Dynamic(emu.pc));
                }
                Ok(#target_step)
            } else {
                emu.pc = #fallthrough;
                emu.update_insn_clock();
                #check
                if emu.should_yield() {
                    return Ok(#step::Dynamic(emu.pc));
                }
                Ok(#fallthrough_step)
            }
        };
        (code, true, 0, 0)
    }

    /// Generates code for ECALL (Environment Call) instruction.
    ///
    /// ECALL invokes system calls. The generated code delegates to the
    /// emulator's generic syscall system and handles return values, extra
    /// cycles, and potential halts.
    fn gen_ecall(
        &self,
        body: BlockBody,
        pc: u64,
        _inst: &Instruction,
    ) -> (TokenStream, bool, usize, usize) {
        let code = quote! {
            // Read the full 32-bit syscall number from t0 (x5)
            // SyscallCode encodes: [ID, Table, Cycles, Unused] in little-endian
            let syscall_id = emu.read_reg_snapshot(5);
            let arg2 = emu.read_reg_c(11); // a1 (x11)
            let arg1 = emu.read_reg_b(10); // a0 (x10)

            // Execute syscall via the generic syscall system
            match emu.execute_syscall(syscall_id, arg1, arg2) {
                Ok((return_value, new_next_pc, extra_cycles, should_halt)) => {
                    // Write return value to t0 (x5).
                    // This must happen at runtime instead of being pre-batched because
                    // ENTER_UNCONSTRAINED mirrors baseline rw_unconstrained() semantics
                    // and does not increment the chunk-split mem_rw counter.
                    emu.write_reg(5, return_value);
                    emu.emit_ecall(#pc, new_next_pc, return_value, arg1, arg2);

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
                    Ok(crate::NextStep::Dynamic(emu.pc))
                }
                Err(e) => Err(e),
            }
        };
        let code = match body {
            BlockBody::Plain => code,
            // The syscall, its precompile and the step's own row write through the core's sink.
            BlockBody::Recorder => quote! {
                emu.with_sink_on_core(rec, |emu| -> Result<crate::NextStep, String> { #code })
            },
        };
        (code, true, 0, 1)
    }

    /// Generates code for EBREAK (breakpoint) instruction.
    fn gen_ebreak(&self, pc: u64) -> (TokenStream, bool, usize, usize) {
        let code = quote! {
            Err(emu.breakpoint(#pc))
        };
        (code, true, 0, 0)
    }

    /// Generates code for UNIMP (Unimplemented) instruction.
    ///
    /// UNIMP is a pseudo-instruction that should always error.
    fn gen_unimp(&self, pc: u64, _inst: &Instruction) -> (TokenStream, bool, usize, usize) {
        let code = quote! {
            emu.update_insn_clock();
            Err(emu.illegal_instruction(#pc))
        };
        (code, true, 0, 0)
    }

    // --- ALU Generators (Non-Terminators) ---

    /// Generates code that dispatches to AOT runtime helpers for ALU ops.
    fn gen_alu_helper(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        imm_helper: &str,
        reg_helper: &str,
    ) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        if inst.imm_b && inst.imm_c {
            let (rd, b, c) = (register(inst.op_a), inst.op_b, inst.op_c);
            let op = match inst.opcode {
                Opcode::ADD => quote! { let a = #b.wrapping_add(#c); },
                Opcode::SUB => quote! { let a = #b.wrapping_sub(#c); },
                Opcode::XOR => quote! { let a = #b ^ #c; },
                Opcode::OR => quote! { let a = #b | #c; },
                Opcode::AND => quote! { let a = #b & #c; },
                Opcode::SLL => {
                    quote! { let a = #b.wrapping_shl((#c & 0x3f) as u32); }
                }
                Opcode::SRL => {
                    quote! { let a = #b.wrapping_shr((#c & 0x3f) as u32); }
                }
                Opcode::SRA => {
                    quote! { let a = ((#b as i64).wrapping_shr((#c & 0x3f) as u32)) as u64; }
                }
                Opcode::SLT => {
                    quote! { let a = if (#b as i64) < (#c as i64) { 1_u64 } else { 0_u64 }; }
                }
                Opcode::SLTU => {
                    quote! { let a = if #b < #c { 1_u64 } else { 0_u64 }; }
                }
                _ => quote! { unreachable!() },
            };

            let (constant, sink) = body.helper("constant");
            quote! {
                #op
                emu.#constant(#sink, #rd, a, #b, #c, #next_pc);
            }
        } else {
            let (rd, rs1, rs2, imm, use_imm) = decode_rr_imm(inst);

            if use_imm {
                let (imm_helper, sink) = body.helper(imm_helper);
                quote! {
                    emu.#imm_helper(#sink, #rd, #rs1, #imm, #next_pc);
                }
            } else {
                let (reg_helper, sink) = body.helper(reg_helper);
                quote! {
                    emu.#reg_helper(#sink, #rd, #rs1, #rs2, #next_pc);
                }
            }
        }
    }

    /// Generates code for register-register operations (R-type only).
    fn gen_rr_helper(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        helper: &str,
    ) -> TokenStream {
        if inst.imm_b || inst.imm_c {
            panic!(
                "AOT build error: unexpected non-R-type encoding for {:?} at PC {:#x} in gen_rr_helper",
                inst.opcode, pc
            );
        }
        let (rd, rs1, rs2) = (
            register(inst.op_a),
            register(inst.op_b),
            register(inst.op_c),
        );
        let next_pc = pc.wrapping_add(4);
        let (helper, sink) = body.helper(helper);

        quote! {
            emu.#helper(#sink, #rd, #rs1, #rs2, #next_pc);
        }
    }

    fn gen_word_alu_helper(
        &self,
        body: BlockBody,
        pc: u64,
        inst: &Instruction,
        reg_helper: &str,
    ) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        if inst.imm_b && inst.imm_c {
            // The interpreter's event carries the operands as the instruction holds them; the
            // word operation takes their low 32 bits.
            let (rd, b, c) = (register(inst.op_a), inst.op_b, inst.op_c);
            let (lhs, rhs) = (b as u32, c as u32);
            let op = match inst.opcode {
                Opcode::ADDW => quote! {
                    let value = u64::from((#lhs).wrapping_add(#rhs));
                    let result = AotEmulatorCore::sign_extend_word_result_u64(value);
                },
                Opcode::SLLW => quote! {
                    let shamt = AotEmulatorCore::word_shift_amount_u32(u64::from(#rhs));
                    let value = u64::from((#lhs).wrapping_shl(shamt));
                    let result = AotEmulatorCore::sign_extend_word_result_u64(value);
                },
                Opcode::SRLW => quote! {
                    let shamt = AotEmulatorCore::word_shift_amount_u32(u64::from(#rhs));
                    let value = u64::from((#lhs).wrapping_shr(shamt));
                    let result = AotEmulatorCore::sign_extend_word_result_u64(value);
                },
                Opcode::SRAW => quote! {
                    let shamt = AotEmulatorCore::word_shift_amount_u32(u64::from(#rhs));
                    let value = ((#lhs as i32).wrapping_shr(shamt)) as u32 as u64;
                    let result = AotEmulatorCore::sign_extend_word_result_u64(value);
                },
                _ => quote! { unreachable!() },
            };

            let (constant, sink) = body.helper("constant");
            quote! {
                #op
                emu.#constant(#sink, #rd, result, #b, #c, #next_pc);
            }
        } else {
            let (rd, rs1, rs2, imm, use_imm) = decode_rr_imm(inst);

            if use_imm {
                let imm_helper = match inst.opcode {
                    Opcode::ADDW => "adiw",
                    Opcode::SLLW => "sliw",
                    Opcode::SRLW => "sriw",
                    Opcode::SRAW => "saiw",
                    other => unreachable!("{other:?} at PC {pc:#x} has no word immediate form"),
                };
                let (imm_helper, sink) = body.helper(imm_helper);
                quote! {
                    emu.#imm_helper(#sink, #rd, #rs1, #imm, #next_pc);
                }
            } else {
                let (reg_helper, sink) = body.helper(reg_helper);
                quote! {
                    emu.#reg_helper(#sink, #rd, #rs1, #rs2, #next_pc);
                }
            }
        }
    }

    /// Generates code for AUIPC (Add Upper Immediate to PC) instruction.
    fn gen_auipc(&self, body: BlockBody, pc: u64, inst: &Instruction) -> TokenStream {
        let (rd, imm) = (register(inst.op_a), inst.op_b);
        let current_pc = pc;
        let next_pc = pc.wrapping_add(4);
        let (helper, sink) = body.helper("apc");

        quote! {
            emu.#helper(#sink, #rd, #current_pc, #imm, #next_pc);
        }
    }

    // --- Memory Generators ---

    /// Generates code for load instructions (LB, LH, LW, LBU, LHU).
    ///
    /// Handles byte, halfword, and word loads with proper sign/zero extension.
    fn gen_load(&self, body: BlockBody, pc: u64, inst: &Instruction) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        let (rd, rs1, imm) = (register(inst.op_a), register(inst.op_b), inst.op_c);

        // The loads that can fault on alignment return a `Result`.
        let (helper, fallible) = match inst.opcode {
            Opcode::LB => ("lb", false),
            Opcode::LH => ("lh", true),
            Opcode::LW => ("lw", true),
            Opcode::LBU => ("lbu", false),
            Opcode::LHU => ("lhu", true),
            Opcode::LWU => ("lwu", true),
            Opcode::LD => ("ld", true),
            _ => return quote! { unreachable!() },
        };
        let (helper, sink) = body.helper(helper);
        let fault = fallible.then(|| quote! { ? });
        quote! {
            emu.#helper(#sink, #rd, #rs1, #imm, #next_pc)#fault;
        }
    }

    /// Generates code for store instructions (SB, SH, SW).
    ///
    /// Handles byte, halfword, and word stores with proper masking.
    fn gen_store(&self, body: BlockBody, pc: u64, inst: &Instruction) -> TokenStream {
        let next_pc = pc.wrapping_add(4);
        // NOTE: Pico's custom instruction encoding stores S-type as:
        // op_a = rs2 (value), op_b = rs1 (base), op_c = imm.
        let (rs2, rs1, imm) = (register(inst.op_a), register(inst.op_b), inst.op_c);

        let (helper, fallible) = match inst.opcode {
            Opcode::SB => ("sb", false),
            Opcode::SH => ("sh", true),
            Opcode::SW => ("sw", true),
            Opcode::SD => ("sd", true),
            _ => return quote! { unreachable!() },
        };
        let (helper, sink) = body.helper(helper);
        let fault = fallible.then(|| quote! { ? });
        quote! {
            emu.#helper(#sink, #rs2, #rs1, #imm, #next_pc)#fault;
        }
    }
}

// --- Helper Functions ---

/// Decodes register-register or register-immediate instruction operands.
///
/// Returns: (rd, rs1, rs2, imm, use_imm)
fn decode_rr_imm(inst: &Instruction) -> (usize, usize, usize, u64, bool) {
    let (rd, rs1) = (register(inst.op_a), register(inst.op_b));
    if inst.imm_c {
        (rd, rs1, 0, inst.op_c, true)
    } else {
        (rd, rs1, register(inst.op_c), 0, false)
    }
}

/// A register operand as an index: the one operand that must be narrow, checked in every build.
fn register(operand: impl Into<u64>) -> usize {
    let operand = operand.into();
    assert!(
        operand < 32,
        "AOT build error: operand {operand} is not a register"
    );
    operand as usize
}

#[cfg(test)]
mod tests {
    use super::{BlockBody, InstructionTranslator};
    use crate::types::{Instruction, Opcode, ProgramInfo};
    use std::collections::HashSet;

    /// Four instructions at 0x1000: a statically known target inside them needs no check.
    fn translator() -> InstructionTranslator {
        let nop = Instruction::new(Opcode::ADD, 0, 0, 0, false, false);
        InstructionTranslator::for_program(&ProgramInfo::new(vec![nop; 4], 0x1000, 0x1000))
    }

    /// The plain body's code and the recording body's for `inst` at `pc`.
    fn bodies_at(translator: &InstructionTranslator, pc: u64, inst: Instruction) -> [String; 2] {
        let leaders = HashSet::new();
        [BlockBody::Plain, BlockBody::Recorder].map(|body| {
            let (code, ..) = translator.translate_body(body, pc, &inst, &leaders);
            code.to_string()
        })
    }

    fn bodies(translator: &InstructionTranslator, inst: Instruction) -> [String; 2] {
        bodies_at(translator, 0x1000, inst)
    }

    /// Whether both bodies check the jump; they must agree, so the snapshot thread and a replay
    /// worker end the same runs.
    fn checks(translator: &InstructionTranslator, inst: Instruction) -> bool {
        let [plain, recorded] = bodies(translator, inst);
        let (plain, recorded) = (
            plain.contains("check_jump_target"),
            recorded.contains("check_jump_target"),
        );
        assert_eq!(plain, recorded, "the two bodies disagree on {inst:?}");
        plain
    }

    /// The generated code checks a jump or branch exactly when its static target is not one of
    /// the program's instructions, as the interpreter does at run time, in both bodies.
    #[test]
    fn a_static_target_is_checked_only_when_it_is_not_an_instruction() {
        let t = translator();
        let jal =
            |offset: i32| Instruction::new(Opcode::JAL, 0, offset as i64 as u64, 0, true, true);
        let beq =
            |offset: i32| Instruction::new(Opcode::BEQ, 0, 0, offset as i64 as u64, false, true);
        for (inst, checked) in [
            (jal(8), false),    // 0x1008, an instruction
            (jal(6), true),     // misaligned
            (jal(16), true),    // 0x1010, one past the end
            (jal(-8), true),    // below the program
            (beq(12), false),   // 0x100c, the last instruction
            (beq(2), true),     // misaligned
            (beq(0x100), true), // outside
        ] {
            assert_eq!(checks(&t, inst), checked, "{inst:?}");
        }
    }

    /// A translator that does not know the program checks every static target.
    #[test]
    fn an_unknown_program_has_every_static_target_checked() {
        let jal = Instruction::new(Opcode::JAL, 1, 8, 0, true, true);
        assert!(checks(&InstructionTranslator::new(), jal));
    }

    /// A JALR's target is known only once its register is read, so its entry checks it before it
    /// writes the link (the runtime's tests hold it to that), and both bodies hand the error on
    /// before the pc moves.
    #[test]
    fn a_jalr_is_checked_by_its_entry_before_the_pc_moves() {
        let jalr = Instruction::new(Opcode::JALR, 1, 1, 0, false, true);
        let [plain, recorded] = bodies(&translator(), jalr);
        for (code, entry) in [(plain, "jalr_no_count"), (recorded, "jalr_direct_rec")] {
            let call = code
                .find(entry)
                .unwrap_or_else(|| panic!("no {entry}: {code}"));
            let (handed_on, moved) = (code[call..].find(") ?"), code.find("emu . pc ="));
            assert!(
                handed_on.is_some_and(|at| moved.is_some_and(|moved| call + at < moved)),
                "{code}"
            );
            assert!(!code.contains("check_jump_target"), "{code}");
        }
    }

    /// A bad `JAL` fails before its link is written, in the recording body as in the plain one.
    #[test]
    fn a_bad_jal_is_checked_before_its_link_is_written() {
        let jal = Instruction::new(Opcode::JAL, 1, 6, 0, true, true);
        let [plain, recorded] = bodies(&translator(), jal);
        for (code, link) in [(plain, "jal_no_count"), (recorded, "jal_direct_rec")] {
            let (check, link) = (code.find("check_jump_target"), code.find(link));
            assert!(check.is_some() && link.is_some() && check < link, "{code}");
        }
    }

    /// `AUIPC` is `ADD rd, imm, pc` with both operands immediates. At pc 2^31, `pc` does not survive
    /// a round trip through u32 (it comes back as 0xffff_ffff_8000_0000), and both bodies take it,
    /// and the sum, as the program holds them.
    #[test]
    fn an_immediate_past_u32_is_the_programs_in_both_bodies() {
        let pc = 0x8000_0000_u64;
        let auipc = Instruction::new(Opcode::ADD, 1, 0x1000, pc, true, true);
        let [plain, recorded] = bodies_at(&translator(), pc, auipc);
        let held = format!("{pc}u64");
        assert!(
            plain.contains(&format!("let a = 4096u64 . wrapping_add ({held})"))
                && plain.contains(&format!(
                    "constant_no_count (emitting , 1usize , a , 4096u64 , {held} ,"
                )),
            "{plain}"
        );
        assert!(
            recorded.contains(&format!(
                "Instruction :: new (Opcode :: ADD , 1u8 , 4096u64 , {held} , true , true)"
            )),
            "{recorded}"
        );
        let narrowed = format!("{}u64", pc as u32 as i32 as i64 as u64);
        for code in [&plain, &recorded] {
            assert!(!code.contains(&narrowed), "{code}");
        }
    }

    /// A helper is handed the immediate whole, as the direct entry is, even one past 32 bits.
    #[test]
    fn a_helper_is_handed_the_immediate_whole() {
        let imm = 1_u64 << 32;
        let addi = Instruction::new(Opcode::ADD, 1, 2, imm, false, true);
        let [plain, recorded] = bodies(&translator(), addi);
        assert!(
            plain.contains(&format!(
                "adi_no_count (emitting , 1usize , 2usize , {imm}u64 ,"
            )),
            "{plain}"
        );
        assert!(
            recorded.contains(&format!(
                "Opcode :: ADD , 1u8 , 2u64 , {imm}u64 , false , true"
            )),
            "{recorded}"
        );
    }

    /// A register operand past `x31` is refused at generation in every build, not only a debug
    /// one.
    #[test]
    #[should_panic(expected = "operand 32 is not a register")]
    fn a_register_operand_past_x31_is_refused() {
        let add = Instruction::new(Opcode::ADD, 1, 32, 2, false, false);
        bodies(&translator(), add);
    }
}
