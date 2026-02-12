use super::{
    constants::{BYTES_PER_WORD, SHIFT_MASK},
    AotEmulatorCore,
};

impl AotEmulatorCore {
    // ========================================================================
    // No-Count Helpers (Block-Level Event Batching)
    // ========================================================================
    //
    // These helpers skip per-op event counting. The generated block must call
    // add_memory_rw_events() with the static event total.
    // ========================================================================

    /// ALU immediate add (no-count): rd = rs1 + imm; pc = next_pc
    #[inline(always)]
    pub fn adi_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let base = self.read_reg_b_tracked(rs1);
        let v = base.wrapping_add(imm);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register add (no-count): rd = rs1 + rs2; pc = next_pc
    #[inline(always)]
    pub fn adr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_add(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate sub (no-count): rd = rs1 - imm; pc = next_pc
    #[inline(always)]
    pub fn sbi_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1).wrapping_sub(imm);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register sub (no-count): rd = rs1 - rs2; pc = next_pc
    #[inline(always)]
    pub fn sbr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_sub(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate xor (no-count): rd = rs1 ^ imm; pc = next_pc
    #[inline(always)]
    pub fn xri_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1) ^ imm;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register xor (no-count): rd = rs1 ^ rs2; pc = next_pc
    #[inline(always)]
    pub fn xrr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1 ^ v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate or (no-count): rd = rs1 | imm; pc = next_pc
    #[inline(always)]
    pub fn ori_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1) | imm;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register or (no-count): rd = rs1 | rs2; pc = next_pc
    #[inline(always)]
    pub fn orr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1 | v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate and (no-count): rd = rs1 & imm; pc = next_pc
    #[inline(always)]
    pub fn ani_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1) & imm;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register and (no-count): rd = rs1 & rs2; pc = next_pc
    #[inline(always)]
    pub fn anr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1 & v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical immediate (no-count): rd = rs1 << (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sli_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1).wrapping_shl(imm & SHIFT_MASK);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical register (no-count): rd = rs1 << (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn slr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_shl(v2 & SHIFT_MASK));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical immediate (no-count): rd = rs1 >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sri_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1).wrapping_shr(imm & SHIFT_MASK);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical register (no-count): rd = rs1 >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn srr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_shr(v2 & SHIFT_MASK));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic immediate (no-count): rd = (rs1 as i32) >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sai_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = (self.read_reg_b_tracked(rs1) as i32).wrapping_shr(imm & SHIFT_MASK) as u32;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic register (no-count): rd = (rs1 as i32) >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sar_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, (v1 as i32).wrapping_shr(v2 & SHIFT_MASK) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate (no-count): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn slti_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1);
        let result = if (v as i32) < (imm as i32) { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register (no-count): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if (v1 as i32) < (v2 as i32) { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate unsigned (no-count): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltiu_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1);
        let result = if v < imm { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register unsigned (no-count): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltru_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if v1 < v2 { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Add upper immediate to PC (no-count): rd = pc + imm; pc = next_pc
    #[inline(always)]
    pub fn apc_no_count(&mut self, rd: usize, pc: u32, imm: u32, next_pc: u32) {
        self.write_reg_no_count(rd, pc.wrapping_add(imm));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load word (no-count): rd = mem_word[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn lw_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u32,
        next_pc: u32,
    ) -> Result<(), String> {
        let base = self.read_reg_b_tracked(rs1);
        let addr = base.wrapping_add(imm);
        if !addr.is_multiple_of(4) {
            return Err(format!("Unaligned LW at {:#x}", addr));
        }
        let v = self.read_mem_constrained(addr);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store word (no-count): mem_word[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sw_no_count(
        &mut self,
        rs2: usize,
        rs1: usize,
        imm: u32,
        next_pc: u32,
    ) -> Result<(), String> {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(4) {
            return Err(format!("Unaligned SW at {:#x}", addr));
        }
        self.write_mem_no_count(addr, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load half (no-count): rd = sign_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lh_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u32,
        next_pc: u32,
    ) -> Result<(), String> {
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LH at {:#x}", addr));
        }
        let word = self.read_mem_constrained(addr & !3);
        let v = if (addr >> 1).is_multiple_of(2) {
            word & 0xFFFF
        } else {
            (word >> 16) & 0xFFFF
        };
        self.write_reg_no_count(rd, ((v as i16) as i32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load half unsigned (no-count): rd = zero_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lhu_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u32,
        next_pc: u32,
    ) -> Result<(), String> {
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LHU at {:#x}", addr));
        }
        let word = self.read_mem_constrained(addr & !3);
        let v = if (addr >> 1).is_multiple_of(2) {
            word & 0xFFFF
        } else {
            (word >> 16) & 0xFFFF
        };
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store half (no-count): mem_half[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sh_no_count(
        &mut self,
        rs2: usize,
        rs1: usize,
        imm: u32,
        next_pc: u32,
    ) -> Result<(), String> {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned SH at {:#x}", addr));
        }
        let word_addr = addr & !(BYTES_PER_WORD - 1);
        let word = self.read_mem_constrained(word_addr);
        let new_word = if (addr >> 1).is_multiple_of(2) {
            (v & 0xFFFF) | (word & 0xFFFF0000)
        } else {
            ((v & 0xFFFF) << 16) | (word & 0x0000FFFF)
        };
        self.write_mem_no_count(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load byte signed (no-count): rd = sign_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lb_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        let word = self.read_mem_constrained(addr & !(BYTES_PER_WORD - 1));
        let byte_idx = (addr % BYTES_PER_WORD) as usize;
        let v = (word.to_le_bytes()[byte_idx] as i8) as i32 as u32;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load byte unsigned (no-count): rd = zero_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lbu_no_count(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        let word = self.read_mem_constrained(addr & !(BYTES_PER_WORD - 1));
        let byte_idx = (addr % BYTES_PER_WORD) as usize;
        let v = word.to_le_bytes()[byte_idx] as u32;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Store byte (no-count): mem_byte[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sb_no_count(&mut self, rs2: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        let word_addr = addr & !(BYTES_PER_WORD - 1);
        let word = self.read_mem_constrained(word_addr);
        let new_word = match addr % BYTES_PER_WORD {
            0 => (v & 0xFF) | (word & 0xFFFFFF00),
            1 => ((v & 0xFF) << 8) | (word & 0xFFFF00FF),
            2 => ((v & 0xFF) << 16) | (word & 0xFF00FFFF),
            _ => ((v & 0xFF) << 24) | (word & 0x00FFFFFF),
        };
        self.write_mem_no_count(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply (no-count): rd = rs1 * rs2; pc = next_pc
    #[inline]
    pub fn mul_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_mul(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-signed (no-count): rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulh_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as i32 as i64;
        let v1 = self.read_reg_b_tracked(rs1) as i32 as i64;
        self.write_reg_no_count(rd, ((v1 * v2) >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high unsigned-unsigned (no-count): rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulhu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as u64;
        let v1 = self.read_reg_b_tracked(rs1) as u64;
        self.write_reg_no_count(rd, ((v1 * v2) >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-unsigned (no-count): rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulhsu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as u64;
        let v1 = self.read_reg_b_tracked(rs1) as i32 as i64 as u64;
        self.write_reg_no_count(rd, ((v1 * v2) >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide signed (no-count): rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn div_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as i32;
        let v1 = self.read_reg_b_tracked(rs1) as i32;
        let rv = if v2 == 0 {
            -1i32 as u32
        } else {
            v1.wrapping_div(v2) as u32
        };
        self.write_reg_no_count(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide unsigned (no-count): rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn divu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = if v2 == 0 {
            u32::MAX
        } else {
            v1.wrapping_div(v2)
        };
        self.write_reg_no_count(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder signed (no-count): rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn rem_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as i32;
        let v1 = self.read_reg_b_tracked(rs1) as i32;
        let rv = if v2 == 0 { v1 } else { v1.wrapping_rem(v2) } as u32;
        self.write_reg_no_count(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder unsigned (no-count): rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn remu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = if v2 == 0 { v1 } else { v1.wrapping_rem(v2) };
        self.write_reg_no_count(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }
}
