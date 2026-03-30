use super::{
    constants::{sign_extend_imm32, BYTES_PER_WORD},
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
    pub fn adi_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let base = self.read_reg_b_tracked(rs1);
        let v = base.wrapping_add(sign_extend_imm32(imm));
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register add (no-count): rd = rs1 + rs2; pc = next_pc
    #[inline(always)]
    pub fn adr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_add(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate sub (no-count): rd = rs1 - imm; pc = next_pc
    #[inline(always)]
    pub fn sbi_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b_tracked(rs1)
            .wrapping_sub(sign_extend_imm32(imm));
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register sub (no-count): rd = rs1 - rs2; pc = next_pc
    #[inline(always)]
    pub fn sbr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_sub(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn addw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value = u64::from(
            (self.read_reg_b_tracked(rs1) as u32).wrapping_add(self.read_reg_c_tracked(rs2) as u32),
        );
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn subw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value = u64::from(
            (self.read_reg_b_tracked(rs1) as u32).wrapping_sub(self.read_reg_c_tracked(rs2) as u32),
        );
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sllw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c_tracked(rs2));
        let value = u64::from((self.read_reg_b_tracked(rs1) as u32).wrapping_shl(shamt));
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn srlw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c_tracked(rs2));
        let value = u64::from((self.read_reg_b_tracked(rs1) as u32).wrapping_shr(shamt));
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sraw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c_tracked(rs2));
        let value = (self.read_reg_b_tracked(rs1) as u32 as i32).wrapping_shr(shamt);
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate xor (no-count): rd = rs1 ^ imm; pc = next_pc
    #[inline(always)]
    pub fn xri_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1) ^ sign_extend_imm32(imm);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register xor (no-count): rd = rs1 ^ rs2; pc = next_pc
    #[inline(always)]
    pub fn xrr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1 ^ v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate or (no-count): rd = rs1 | imm; pc = next_pc
    #[inline(always)]
    pub fn ori_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1) | sign_extend_imm32(imm);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register or (no-count): rd = rs1 | rs2; pc = next_pc
    #[inline(always)]
    pub fn orr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1 | v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU immediate and (no-count): rd = rs1 & imm; pc = next_pc
    #[inline(always)]
    pub fn ani_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1) & sign_extend_imm32(imm);
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// ALU register and (no-count): rd = rs1 & rs2; pc = next_pc
    #[inline(always)]
    pub fn anr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1 & v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical immediate (no-count): rd = rs1 << (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sli_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b_tracked(rs1)
            .wrapping_shl(Self::shift_amount_u32(imm));
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift left logical register (no-count): rd = rs1 << (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn slr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_shl(Self::shift_amount_u32(v2)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical immediate (no-count): rd = rs1 >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sri_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b_tracked(rs1)
            .wrapping_shr(Self::shift_amount_u32(imm));
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right logical register (no-count): rd = rs1 >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn srr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_shr(Self::shift_amount_u32(v2)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic immediate (no-count): rd = (rs1 as i64) >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sai_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = (self.read_reg_b_tracked(rs1) as i64).wrapping_shr(Self::shift_amount_u32(imm));
        self.write_reg_no_count(rd, v as u64);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Shift right arithmetic register (no-count): rd = (rs1 as i64) >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sar_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let v = (v1 as i64).wrapping_shr(Self::shift_amount_u32(v2));
        self.write_reg_no_count(rd, v as u64);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate (no-count): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn slti_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1);
        let result = if (v as i64) < (sign_extend_imm32(imm) as i64) {
            1
        } else {
            0
        };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register (no-count): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltr_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if (v1 as i64) < (v2 as i64) { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than immediate unsigned (no-count): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltiu_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1);
        let imm = sign_extend_imm32(imm);
        let result = if v < imm { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Set less than register unsigned (no-count): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltru_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if v1 < v2 { 1 } else { 0 };
        self.write_reg_no_count(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Add upper immediate to PC (no-count): rd = pc + imm; pc = next_pc
    #[inline(always)]
    pub fn apc_no_count(&mut self, rd: usize, pc: u64, imm: u64, next_pc: u64) {
        self.write_reg_no_count(rd, pc.wrapping_add(sign_extend_imm32(imm)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load word (no-count): rd = mem_word[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn lw_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let base = self.read_reg_b_tracked(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned LW at {:#x}", addr));
        }
        let v = self.read_mem_word_constrained(addr);
        self.write_reg_no_count(rd, (v as u32 as i32) as i64 as u64);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load word unsigned (no-count): rd = zero_ext(mem_word[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lwu_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let base = self.read_reg_b_tracked(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned LWU at {:#x}", addr));
        }
        let value = self.read_mem_word_constrained(addr);
        self.write_reg_no_count(rd, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load doubleword (no-count): rd = mem_dword[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn ld_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let base = self.read_reg_b_tracked(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(8) {
            return Err(format!("Unaligned LD at {:#x}", addr));
        }
        let value = self.read_mem_dword_constrained(addr);
        self.write_reg_no_count(rd, value);
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
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned SW at {:#x}", addr));
        }
        self.write_mem_word_no_count(addr, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Store doubleword (no-count): mem_dword[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sd_no_count(
        &mut self,
        rs2: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(8) {
            return Err(format!("Unaligned SD at {:#x}", addr));
        }
        self.write_mem_dword_no_count(addr, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn mulw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value = u64::from(
            (self.read_reg_b_tracked(rs1) as u32).wrapping_mul(self.read_reg_c_tracked(rs2) as u32),
        );
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn divw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32 as i32;
        let rhs = self.read_reg_c_tracked(rs2) as u32 as i32;
        let value = if rhs == 0 {
            -1i32
        } else if lhs == i32::MIN && rhs == -1 {
            i32::MIN
        } else {
            lhs.wrapping_div(rhs)
        };
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn divuw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32;
        let rhs = self.read_reg_c_tracked(rs2) as u32;
        let value = if rhs == 0 {
            u32::MAX
        } else {
            lhs.wrapping_div(rhs)
        };
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(u64::from(value)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn remw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32 as i32;
        let rhs = self.read_reg_c_tracked(rs2) as u32 as i32;
        let value = if rhs == 0 {
            lhs
        } else if lhs == i32::MIN && rhs == -1 {
            0
        } else {
            lhs.wrapping_rem(rhs)
        };
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn remuw_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32;
        let rhs = self.read_reg_c_tracked(rs2) as u32;
        let value = if rhs == 0 { lhs } else { lhs.wrapping_rem(rhs) };
        self.write_reg_no_count(rd, Self::sign_extend_word_result_u64(u64::from(value)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load half (no-count): rd = sign_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lh_no_count(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LH at {:#x}", addr));
        }
        let word = self.read_mem_word_constrained(addr & !u64::from(3u32));
        let v = Self::read_u16_from_word(word, addr);
        self.write_reg_no_count(rd, (v as i16) as i64 as u64);
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
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LHU at {:#x}", addr));
        }
        let word = self.read_mem_word_constrained(addr & !u64::from(3u32));
        self.write_reg_no_count(rd, u64::from(Self::read_u16_from_word(word, addr)));
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
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned SH at {:#x}", addr));
        }
        let word_addr = addr & !u64::from(BYTES_PER_WORD - 1);
        let word = self.read_mem_word_constrained(word_addr);
        let new_word = Self::write_u16_into_word(word, addr, v);
        self.write_mem_word_no_count(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    /// Load byte signed (no-count): rd = sign_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lb_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        let word = self.read_mem_word_constrained(addr & !u64::from(BYTES_PER_WORD - 1));
        let v = Self::read_u8_from_word(word, addr) as i8 as i64 as u64;
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Load byte unsigned (no-count): rd = zero_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lbu_no_count(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        let word = self.read_mem_word_constrained(addr & !u64::from(BYTES_PER_WORD - 1));
        let v = u64::from(Self::read_u8_from_word(word, addr));
        self.write_reg_no_count(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Store byte (no-count): mem_byte[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sb_no_count(&mut self, rs2: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        let word_addr = addr & !u64::from(BYTES_PER_WORD - 1);
        let word = self.read_mem_word_constrained(word_addr);
        let new_word = Self::write_u8_into_word(word, addr, v);
        self.write_mem_word_no_count(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply (no-count): rd = rs1 * rs2; pc = next_pc
    #[inline]
    pub fn mul_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, v1.wrapping_mul(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-signed (no-count): rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline]
    pub fn mulh_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, Self::rv64_mulh_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high unsigned-unsigned (no-count): rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline]
    pub fn mulhu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, Self::rv64_mulhu_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Multiply high signed-unsigned (no-count): rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline]
    pub fn mulhsu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, Self::rv64_mulhsu_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide signed (no-count): rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn div_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, Self::rv64_div_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Divide unsigned (no-count): rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn divu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = Self::rv64_divu_result_u64(v1, v2);
        self.write_reg_no_count(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder signed (no-count): rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn rem_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_no_count(rd, Self::rv64_rem_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    /// Remainder unsigned (no-count): rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn remu_no_count(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = Self::rv64_remu_result_u64(v1, v2);
        self.write_reg_no_count(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }
}
