use pico_vm::chips::chips::riscv_memory::event::MemoryAccessPosition;

use super::{
    constants::BYTES_PER_WORD,
    sink::{by_sink, LentSink},
    state::Touch,
    AotEmulatorCore, Recorder,
};

impl AotEmulatorCore {
    // ========================================================================
    // No-Count Helpers (Block-Level Event Batching)
    // ========================================================================
    //
    // These helpers skip per-op event counting. The generated block must call
    // add_memory_rw_events() with the static event total.
    //
    // Each reads its registers in the interpreter's order, operand `c` before `b` before `a`: an
    // instruction that reads one register twice leaves it at the later timestamp, and the record
    // a register holds at a chunk boundary is what the snapshot hands the replay worker. Each
    // body is generic over whether it writes the instruction's events, which it writes before the
    // clock moves on: the instruction's pc is `next_pc - 4`, since none of these is a jump.
    // `emitting` is [`Self::is_emitting`] as the generated block read it on entry, and the helper
    // runs the body that matches it. An immediate is the instruction's operand as the program
    // holds it, as the interpreter takes it.
    // ========================================================================

    /// ALU immediate add (no-count): rd = rs1 + imm; pc = next_pc
    #[inline(always)]
    pub fn adi_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.adi(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn adi<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_add(c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register add (no-count): rd = rs1 + rs2; pc = next_pc
    #[inline(always)]
    pub fn adr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.adr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn adr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_add(c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate sub (no-count): rd = rs1 - imm; pc = next_pc
    #[inline(always)]
    pub fn sbi_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.sbi(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn sbi<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_sub(c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register sub (no-count): rd = rs1 - rs2; pc = next_pc
    #[inline(always)]
    pub fn sbr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sbr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn sbr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_sub(c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn addw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.addw(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn addw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(u64::from((b as u32).wrapping_add(c as u32)));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn subw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.subw(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn subw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(u64::from((b as u32).wrapping_sub(c as u32)));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sllw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sllw(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn sllw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(u64::from(
            (b as u32).wrapping_shl(Self::word_shift_amount_u32(c)),
        ));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn srlw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.srlw(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn srlw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(u64::from(
            (b as u32).wrapping_shr(Self::word_shift_amount_u32(c)),
        ));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sraw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sraw(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn sraw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(
            (b as u32 as i32).wrapping_shr(Self::word_shift_amount_u32(c)) as u32 as u64,
        );
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate xor (no-count): rd = rs1 ^ imm; pc = next_pc
    #[inline(always)]
    pub fn xri_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.xri(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn xri<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b ^ c;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register xor (no-count): rd = rs1 ^ rs2; pc = next_pc
    #[inline(always)]
    pub fn xrr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.xrr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn xrr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b ^ c;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate or (no-count): rd = rs1 | imm; pc = next_pc
    #[inline(always)]
    pub fn ori_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.ori(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn ori<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b | c;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register or (no-count): rd = rs1 | rs2; pc = next_pc
    #[inline(always)]
    pub fn orr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.orr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn orr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b | c;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate and (no-count): rd = rs1 & imm; pc = next_pc
    #[inline(always)]
    pub fn ani_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.ani(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn ani<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b & c;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register and (no-count): rd = rs1 & rs2; pc = next_pc
    #[inline(always)]
    pub fn anr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.anr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn anr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b & c;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical immediate (no-count): rd = rs1 << (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sli_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.sli(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn sli<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_shl(Self::shift_amount_u32(c));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical register (no-count): rd = rs1 << (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn slr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.slr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn slr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_shl(Self::shift_amount_u32(c));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical immediate (no-count): rd = rs1 >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sri_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.sri(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn sri<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_shr(Self::shift_amount_u32(c));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical register (no-count): rd = rs1 >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn srr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.srr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn srr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_shr(Self::shift_amount_u32(c));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic immediate (no-count): rd = (rs1 as i64) >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sai_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.sai(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn sai<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = (b as i64).wrapping_shr(Self::shift_amount_u32(c)) as u64;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic register (no-count): rd = (rs1 as i64) >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sar_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sar(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn sar<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = (b as i64).wrapping_shr(Self::shift_amount_u32(c)) as u64;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate (no-count): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn slti_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.slti(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn slti<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = u64::from((b as i64) < (c as i64));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register (no-count): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sltr(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn sltr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = u64::from((b as i64) < (c as i64));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate unsigned (no-count): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltiu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sltiu(rd, rs1, imm, next_pc))
    }

    #[inline(always)]
    fn sltiu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = u64::from(b < c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register unsigned (no-count): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltru_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.sltru(rd, rs1, rs2, next_pc))
    }

    #[inline(always)]
    fn sltru<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = u64::from(b < c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Add upper immediate to PC (no-count): rd = pc + imm; pc = next_pc
    #[inline(always)]
    pub fn apc_no_count(&mut self, emitting: bool, rd: usize, pc: u64, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.apc(rd, pc, imm, next_pc))
    }

    #[inline(always)]
    fn apc<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        pc: u64,
        imm: u64,
        next_pc: u64,
    ) {
        let a = pc.wrapping_add(imm);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_cpu(sink, pc, next_pc, a, imm, imm);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load word (no-count): rd = mem_word[rs1 + imm]; pc = next_pc
    #[inline(always)]
    pub fn lw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.lw(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn lw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned LW at {:#x}", addr));
        }
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = (Self::extract_word(dword, addr) as u32 as i32) as i64 as u64;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load word unsigned (no-count): rd = zero_ext(mem_word[rs1 + imm]); pc = next_pc
    #[inline(always)]
    pub fn lwu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.lwu(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn lwu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned LWU at {:#x}", addr));
        }
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = Self::extract_word(dword, addr);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load doubleword (no-count): rd = mem_dword[rs1 + imm]; pc = next_pc
    #[inline(always)]
    pub fn ld_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.ld(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn ld<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(8) {
            return Err(format!("Unaligned LD at {:#x}", addr));
        }
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = dword;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store word (no-count): mem_word[rs1 + imm] = rs2; pc = next_pc
    #[inline(always)]
    pub fn sw_no_count(
        &mut self,
        emitting: bool,
        rs2: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.sw(rs2, rs1, imm, next_pc))
    }

    #[inline]
    fn sw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rs2: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned SW at {:#x}", addr));
        }
        let dword = self.write_mem_word_no_count_impl::<EMIT>(sink.as_deref_mut(), addr, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store doubleword (no-count): mem_dword[rs1 + imm] = rs2; pc = next_pc
    #[inline(always)]
    pub fn sd_no_count(
        &mut self,
        emitting: bool,
        rs2: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.sd(rs2, rs1, imm, next_pc))
    }

    #[inline]
    fn sd<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rs2: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(8) {
            return Err(format!("Unaligned SD at {:#x}", addr));
        }
        self.write_mem_dword_no_count_impl::<EMIT>(sink.as_deref_mut(), addr, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, a);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline(always)]
    pub fn mulw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.mulw(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn mulw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(u64::from((b as u32).wrapping_mul(c as u32)));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn divw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.divw(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn divw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let (lhs, rhs) = (b as u32 as i32, c as u32 as i32);
        let value = if rhs == 0 {
            -1i32
        } else if lhs == i32::MIN && rhs == -1 {
            i32::MIN
        } else {
            lhs.wrapping_div(rhs)
        };
        let a = Self::sign_extend_word_result_u64(value as u32 as u64);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn divuw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.divuw(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn divuw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let (lhs, rhs) = (b as u32, c as u32);
        let value = if rhs == 0 {
            u32::MAX
        } else {
            lhs.wrapping_div(rhs)
        };
        let a = Self::sign_extend_word_result_u64(u64::from(value));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn remw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.remw(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn remw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let (lhs, rhs) = (b as u32 as i32, c as u32 as i32);
        let value = if rhs == 0 {
            lhs
        } else if lhs == i32::MIN && rhs == -1 {
            0
        } else {
            lhs.wrapping_rem(rhs)
        };
        let a = Self::sign_extend_word_result_u64(value as u32 as u64);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn remuw_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.remuw(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn remuw<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let (lhs, rhs) = (b as u32, c as u32);
        let value = if rhs == 0 { lhs } else { lhs.wrapping_rem(rhs) };
        let a = Self::sign_extend_word_result_u64(u64::from(value));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load half (no-count): rd = sign_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline(always)]
    pub fn lh_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.lh(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn lh<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LH at {:#x}", addr));
        }
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = (Self::read_u16_from_word(dword, addr) as i16) as i64 as u64;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load half unsigned (no-count): rd = zero_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline(always)]
    pub fn lhu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.lhu(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn lhu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LHU at {:#x}", addr));
        }
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = u64::from(Self::read_u16_from_word(dword, addr));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store half (no-count): mem_half[rs1 + imm] = rs2; pc = next_pc
    #[inline(always)]
    pub fn sh_no_count(
        &mut self,
        emitting: bool,
        rs2: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        by_sink!(emitting, self.sh(rs2, rs1, imm, next_pc))
    }

    #[inline]
    fn sh<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rs2: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned SH at {:#x}", addr));
        }
        let dword = self.write_mem_dword_merged_no_count::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            |word| Self::write_u16_into_word(word, addr, a),
        );
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load byte signed (no-count): rd = sign_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline(always)]
    pub fn lb_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.lb(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn lb<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = Self::read_u8_from_word(dword, addr) as i8 as i64 as u64;
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load byte unsigned (no-count): rd = zero_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline(always)]
    pub fn lbu_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.lbu(rd, rs1, imm, next_pc))
    }

    #[inline]
    fn lbu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let addr = b.wrapping_add(c);
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        let a = u64::from(Self::read_u8_from_word(dword, addr));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Store byte (no-count): mem_byte[rs1 + imm] = rs2; pc = next_pc
    #[inline(always)]
    pub fn sb_no_count(&mut self, emitting: bool, rs2: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(emitting, self.sb(rs2, rs1, imm, next_pc))
    }

    #[inline]
    fn sb<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rs2: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::A);
        let addr = b.wrapping_add(c);
        let dword = self.write_mem_dword_merged_no_count::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            |word| Self::write_u8_into_word(word, addr, a),
        );
        if EMIT {
            self.record_memory(sink, next_pc.wrapping_sub(4), a, b, c, dword);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply (no-count): rd = rs1 * rs2; pc = next_pc
    #[inline(always)]
    pub fn mul_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.mul(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn mul<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = b.wrapping_mul(c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-signed (no-count): rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline(always)]
    pub fn mulh_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.mulh(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn mulh<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_mulh_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high unsigned-unsigned (no-count): rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline(always)]
    pub fn mulhu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.mulhu(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn mulhu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_mulhu_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-unsigned (no-count): rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline(always)]
    pub fn mulhsu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.mulhsu(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn mulhsu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_mulhsu_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide signed (no-count): rd = rs1 / rs2; pc = next_pc
    #[inline(always)]
    pub fn div_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.div(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn div<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_div_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide unsigned (no-count): rd = rs1 / rs2; pc = next_pc
    #[inline(always)]
    pub fn divu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.divu(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn divu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_divu_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder signed (no-count): rd = rs1 % rs2; pc = next_pc
    #[inline(always)]
    pub fn rem_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.rem(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn rem<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_rem_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder unsigned (no-count): rd = rs1 % rs2; pc = next_pc
    #[inline(always)]
    pub fn remu_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.remu(rd, rs1, rs2, next_pc))
    }

    #[inline]
    fn remu<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        rs2: usize,
        next_pc: u64,
    ) {
        let c = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::C);
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::rv64_remu_result_u64(b, c);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    // ========================================================================
    // Jumps, Branches and the Folded Forms
    // ========================================================================
    //
    // What the code generator once wrote out inline, so that every instruction of a block but
    // `ECALL` takes the block's `emitting`. A jump or a branch leaves the pc, the clock and the
    // block's exit to the generated code, and returns what the exit needs. `imm` is the
    // instruction's immediate as the program holds it, as for the helpers above.
    // ========================================================================

    /// Jump and link (no-count): rd = pc + 4. The generated code jumps to pc + imm.
    #[inline(always)]
    pub fn jal_no_count(&mut self, emitting: bool, rd: usize, pc: u64, imm: u64) {
        by_sink!(emitting, self.jal(rd, pc, imm))
    }

    #[inline(always)]
    fn jal<const EMIT: bool>(&mut self, mut sink: LentSink<'_>, rd: usize, pc: u64, imm: u64) {
        let return_addr = pc.wrapping_add(4);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, return_addr);
        if EMIT {
            self.record_cpu(sink, pc, pc.wrapping_add(imm), return_addr, imm, 0);
        }
    }

    /// Jump and link register (no-count): checks the target, (rs1 + imm) & !1, then rd = pc + 4;
    /// returns the target. The check comes before the link, as in the interpreter, so a bad jump
    /// leaves rd as it was.
    ///
    /// # Errors
    ///
    /// [`Self::check_jump_target`]'s, for a misaligned target or one outside the program.
    #[inline(always)]
    pub fn jalr_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        rs1: usize,
        pc: u64,
        imm: u64,
    ) -> Result<u64, String> {
        by_sink!(emitting, self.jalr(rd, rs1, pc, imm))
    }

    #[inline(always)]
    fn jalr<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        pc: u64,
        imm: u64,
    ) -> Result<u64, String> {
        let base = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let target = base.wrapping_add(imm) & !1;
        self.check_jump_target(pc, target)?;
        let return_addr = pc.wrapping_add(4);
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, return_addr);
        if EMIT {
            self.record_cpu(sink, pc, target, return_addr, base, imm);
        }
        Ok(target)
    }

    /// Branch if equal (no-count): whether rs1 == rs2.
    #[inline(always)]
    pub fn beq_no_count(
        &mut self,
        emitting: bool,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
    ) -> bool {
        by_sink!(emitting, self.branch(rs1, rs2, pc, imm, |a, b| a == b))
    }

    /// Branch if not equal (no-count): whether rs1 != rs2.
    #[inline(always)]
    pub fn bne_no_count(
        &mut self,
        emitting: bool,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
    ) -> bool {
        by_sink!(emitting, self.branch(rs1, rs2, pc, imm, |a, b| a != b))
    }

    /// Branch if less than, signed (no-count): whether rs1 < rs2.
    #[inline(always)]
    pub fn blt_no_count(
        &mut self,
        emitting: bool,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
    ) -> bool {
        by_sink!(
            emitting,
            self.branch(rs1, rs2, pc, imm, |a, b| (a as i64) < (b as i64))
        )
    }

    /// Branch if greater or equal, signed (no-count): whether rs1 >= rs2.
    #[inline(always)]
    pub fn bge_no_count(
        &mut self,
        emitting: bool,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
    ) -> bool {
        by_sink!(
            emitting,
            self.branch(rs1, rs2, pc, imm, |a, b| (a as i64) >= (b as i64))
        )
    }

    /// Branch if less than, unsigned (no-count): whether rs1 < rs2.
    #[inline(always)]
    pub fn bltu_no_count(
        &mut self,
        emitting: bool,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
    ) -> bool {
        by_sink!(emitting, self.branch(rs1, rs2, pc, imm, |a, b| a < b))
    }

    /// Branch if greater or equal, unsigned (no-count): whether rs1 >= rs2.
    #[inline(always)]
    pub fn bgeu_no_count(
        &mut self,
        emitting: bool,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
    ) -> bool {
        by_sink!(emitting, self.branch(rs1, rs2, pc, imm, |a, b| a >= b))
    }

    /// A branch comparing rs1, operand `a`, with rs2, operand `b`, by `taken`.
    #[inline(always)]
    fn branch<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rs1: usize,
        rs2: usize,
        pc: u64,
        imm: u64,
        taken: impl FnOnce(u64, u64) -> bool,
    ) -> bool {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs2, MemoryAccessPosition::B);
        let a = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::A);
        let taken = taken(a, b);
        if EMIT {
            let next_pc = if taken {
                pc.wrapping_add(imm)
            } else {
                pc.wrapping_add(4)
            };
            self.record_cpu(sink, pc, next_pc, a, b, imm);
        }
        taken
    }

    /// An ALU or word instruction on two immediates (no-count), whose result `a` the code generator
    /// folded from its operands `b` and `c`, as the instruction's event carries them: rd = a;
    /// pc = next_pc.
    #[inline(always)]
    pub fn constant_no_count(
        &mut self,
        emitting: bool,
        rd: usize,
        a: u64,
        b: u64,
        c: u64,
        next_pc: u64,
    ) {
        by_sink!(emitting, self.constant(rd, a, b, c, next_pc))
    }

    #[inline(always)]
    fn constant<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        a: u64,
        b: u64,
        c: u64,
        next_pc: u64,
    ) {
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Word add immediate (no-count): rd = sext((rs1 + imm)[31:0]); pc = next_pc
    #[inline(always)]
    pub fn adiw_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(
            emitting,
            self.word_immediate(rd, rs1, imm, next_pc, |b, imm| {
                u64::from(b.wrapping_add(imm))
            })
        )
    }

    /// Word shift left logical immediate (no-count): rd = sext((rs1 << shamt)[31:0]); pc = next_pc
    #[inline(always)]
    pub fn sliw_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(
            emitting,
            self.word_immediate(rd, rs1, imm, next_pc, |b, imm| {
                u64::from(b.wrapping_shl(Self::word_shift_amount_u32(u64::from(imm))))
            })
        )
    }

    /// Word shift right logical immediate (no-count): rd = sext(rs1[31:0] >> shamt); pc = next_pc
    #[inline(always)]
    pub fn sriw_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(
            emitting,
            self.word_immediate(rd, rs1, imm, next_pc, |b, imm| {
                u64::from(b.wrapping_shr(Self::word_shift_amount_u32(u64::from(imm))))
            })
        )
    }

    /// Word shift right arithmetic immediate (no-count): rd = sext(rs1[31:0] >>> shamt);
    /// pc = next_pc
    #[inline(always)]
    pub fn saiw_no_count(&mut self, emitting: bool, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        by_sink!(
            emitting,
            self.word_immediate(rd, rs1, imm, next_pc, |b, imm| {
                (b as i32).wrapping_shr(Self::word_shift_amount_u32(u64::from(imm))) as u32 as u64
            })
        )
    }

    /// A word instruction on rs1 and an immediate: `word` takes the low words of rs1 and of the
    /// immediate and returns the word result, which is sign-extended into rd.
    #[inline(always)]
    fn word_immediate<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        rd: usize,
        rs1: usize,
        c: u64,
        next_pc: u64,
        word: impl FnOnce(u32, u32) -> u64,
    ) {
        let b = self.read_reg_at::<EMIT>(sink.as_deref_mut(), rs1, MemoryAccessPosition::B);
        let a = Self::sign_extend_word_result_u64(word(b as u32, c as u32));
        self.set_reg::<EMIT>(sink.as_deref_mut(), rd, a);
        if EMIT {
            self.record_alu(sink, next_pc.wrapping_sub(4), a, b, c);
        }
        self.pc = next_pc;
        self.update_insn_clock();
    }
}

/// `$entry(&mut self, rec, args)`: the helper's emitting body `$body`, writing into the sink `rec`
/// holds with no test of the core's and no lend. A recording block writes every instruction but
/// `ECALL` directly (`recorder.rs`); these are for a branch or `JAL` whose target no row holds
/// (rows hold pcs as `u32`).
macro_rules! recorded {
    ($($entry:ident($($arg:ident: $ty:ty),*) $(-> $ret:ty)? => $body:ident($($call:expr),*);)*) => {
        impl AotEmulatorCore {
            $(
                #[inline(always)]
                pub fn $entry(&mut self, rec: &mut Recorder, $($arg: $ty),*) $(-> $ret)? {
                    self.$body::<true>(rec.sink(), $($call),*)
                }
            )*
        }
    };
}

recorded! {
    jal_rec(rd: usize, pc: u64, imm: u64) => jal(rd, pc, imm);
    beq_rec(rs1: usize, rs2: usize, pc: u64, imm: u64) -> bool
        => branch(rs1, rs2, pc, imm, |a, b| a == b);
    bne_rec(rs1: usize, rs2: usize, pc: u64, imm: u64) -> bool
        => branch(rs1, rs2, pc, imm, |a, b| a != b);
    blt_rec(rs1: usize, rs2: usize, pc: u64, imm: u64) -> bool
        => branch(rs1, rs2, pc, imm, |a, b| (a as i64) < (b as i64));
    bge_rec(rs1: usize, rs2: usize, pc: u64, imm: u64) -> bool
        => branch(rs1, rs2, pc, imm, |a, b| (a as i64) >= (b as i64));
    bltu_rec(rs1: usize, rs2: usize, pc: u64, imm: u64) -> bool
        => branch(rs1, rs2, pc, imm, |a, b| a < b);
    bgeu_rec(rs1: usize, rs2: usize, pc: u64, imm: u64) -> bool
        => branch(rs1, rs2, pc, imm, |a, b| a >= b);
}
