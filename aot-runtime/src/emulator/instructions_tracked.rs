use super::{
    constants::{BYTES_PER_WORD, SHIFT_MASK},
    AotEmulatorCore,
};

impl AotEmulatorCore {
    // ========================================================================
    // Tracked ALU Helpers (Batch-Mode Optimized)
    // ========================================================================
    //
    // These helpers use unconditional tracking variants for better performance
    // in batch mode where tracking is always enabled.
    // ========================================================================

    /// ALU immediate add (tracked): rd = rs1 + imm; pc = next_pc
    #[inline(always)]
    pub fn adi_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let base = self.read_reg_b_tracked(rs1);
        let v = base.wrapping_add(imm);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register add (tracked): rd = rs1 + rs2; pc = next_pc
    #[inline(always)]
    pub fn adr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_add(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate sub (tracked): rd = rs1 - imm; pc = next_pc
    #[inline(always)]
    pub fn sbi_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1).wrapping_sub(imm);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register sub (tracked): rd = rs1 - rs2; pc = next_pc
    #[inline(always)]
    pub fn sbr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_sub(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate xor (tracked): rd = rs1 ^ imm; pc = next_pc
    #[inline(always)]
    pub fn xri_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1) ^ imm;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register xor (tracked): rd = rs1 ^ rs2; pc = next_pc
    #[inline(always)]
    pub fn xrr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1 ^ v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate or (tracked): rd = rs1 | imm; pc = next_pc
    #[inline(always)]
    pub fn ori_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1) | imm;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register or (tracked): rd = rs1 | rs2; pc = next_pc
    #[inline(always)]
    pub fn orr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1 | v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate and (tracked): rd = rs1 & imm; pc = next_pc
    #[inline(always)]
    pub fn ani_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1) & imm;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register and (tracked): rd = rs1 & rs2; pc = next_pc
    #[inline(always)]
    pub fn anr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1 & v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical immediate (tracked): rd = rs1 << (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sli_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1).wrapping_shl(imm & SHIFT_MASK);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical register (tracked): rd = rs1 << (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn slr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_shl(v2 & SHIFT_MASK));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical immediate (tracked): rd = rs1 >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sri_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1).wrapping_shr(imm & SHIFT_MASK);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical register (tracked): rd = rs1 >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn srr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_shr(v2 & SHIFT_MASK));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic immediate (tracked): rd = (rs1 as i32) >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sai_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = (self.read_reg_b_tracked(rs1) as i32).wrapping_shr(imm & SHIFT_MASK) as u32;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic register (tracked): rd = (rs1 as i32) >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sar_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, (v1 as i32).wrapping_shr(v2 & SHIFT_MASK) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate (tracked): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn slti_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1);
        let result = if (v as i32) < (imm as i32) { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register (tracked): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if (v1 as i32) < (v2 as i32) { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate unsigned (tracked): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltiu_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b_tracked(rs1);
        let result = if v < imm { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register unsigned (tracked): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltru_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if v1 < v2 { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Add upper immediate to PC (tracked): rd = pc + imm; pc = next_pc
    #[inline(always)]
    pub fn apc_tracked(&mut self, rd: usize, pc: u32, imm: u32, next_pc: u32) {
        self.write_reg_tracked(rd, pc.wrapping_add(imm));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load word (tracked): rd = mem_word[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn lw_tracked(
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
        let v = self.read_mem(addr);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store word (tracked): mem_word[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sw_tracked(
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
        self.write_mem(addr, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load half (tracked): rd = sign_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lh_tracked(
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
        let word = self.read_mem(addr & !3);
        let v = if (addr >> 1).is_multiple_of(2) {
            word & 0xFFFF
        } else {
            (word >> 16) & 0xFFFF
        };
        self.write_reg_tracked(rd, ((v as i16) as i32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load half unsigned (tracked): rd = zero_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lhu_tracked(
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
        let word = self.read_mem(addr & !3);
        let v = if (addr >> 1).is_multiple_of(2) {
            word & 0xFFFF
        } else {
            (word >> 16) & 0xFFFF
        };
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store half (tracked): mem_half[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sh_tracked(
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
        let word = self.read_mem(word_addr);
        let new_word = if (addr >> 1).is_multiple_of(2) {
            (v & 0xFFFF) | (word & 0xFFFF0000)
        } else {
            ((v & 0xFFFF) << 16) | (word & 0x0000FFFF)
        };
        self.write_mem(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load byte signed (tracked): rd = sign_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lb_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        let word = self.read_mem(addr & !(BYTES_PER_WORD - 1));
        let byte_idx = (addr % BYTES_PER_WORD) as usize;
        let v = (word.to_le_bytes()[byte_idx] as i8) as i32 as u32;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load byte unsigned (tracked): rd = zero_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lbu_tracked(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        let word = self.read_mem(addr & !(BYTES_PER_WORD - 1));
        let byte_idx = (addr % BYTES_PER_WORD) as usize;
        let v = word.to_le_bytes()[byte_idx] as u32;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Store byte (tracked): mem_byte[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sb_tracked(&mut self, rs2: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self.read_reg_b_tracked(rs1).wrapping_add(imm);
        let word_addr = addr & !(BYTES_PER_WORD - 1);
        let word = self.read_mem(word_addr);
        let new_word = match addr % BYTES_PER_WORD {
            0 => (v & 0xFF) | (word & 0xFFFFFF00),
            1 => ((v & 0xFF) << 8) | (word & 0xFFFF00FF),
            2 => ((v & 0xFF) << 16) | (word & 0xFF00FFFF),
            _ => ((v & 0xFF) << 24) | (word & 0x00FFFFFF),
        };
        self.write_mem(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply (tracked): rd = rs1 * rs2; pc = next_pc
    #[inline]
    pub fn mul_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_mul(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-signed (tracked): rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulh_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as i32 as i64;
        let v1 = self.read_reg_b_tracked(rs1) as i32 as i64;
        self.write_reg_tracked(rd, ((v1 * v2) >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high unsigned-unsigned (tracked): rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulhu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as u64;
        let v1 = self.read_reg_b_tracked(rs1) as u64;
        self.write_reg_tracked(rd, ((v1 * v2) >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-unsigned (tracked): rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulhsu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as u64;
        let v1 = self.read_reg_b_tracked(rs1) as i32 as i64 as u64;
        self.write_reg_tracked(rd, ((v1 * v2) >> 32) as u32);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide signed (tracked): rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn div_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as i32;
        let v1 = self.read_reg_b_tracked(rs1) as i32;
        let rv = if v2 == 0 {
            -1i32 as u32
        } else {
            v1.wrapping_div(v2) as u32
        };
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide unsigned (tracked): rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn divu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = if v2 == 0 {
            u32::MAX
        } else {
            v1.wrapping_div(v2)
        };
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder signed (tracked): rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn rem_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2) as i32;
        let v1 = self.read_reg_b_tracked(rs1) as i32;
        let rv = if v2 == 0 { v1 } else { v1.wrapping_rem(v2) } as u32;
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder unsigned (tracked): rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn remu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = if v2 == 0 { v1 } else { v1.wrapping_rem(v2) };
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }
}
