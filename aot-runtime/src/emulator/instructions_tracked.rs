use super::{
    constants::{sign_extend_imm32, SHIFT_MASK},
    AotEmulatorCore,
};

impl AotEmulatorCore {
    #[inline(always)]
    fn shift_u32(value: u64) -> u32 {
        (value & u64::from(SHIFT_MASK)) as u32
    }

    // ========================================================================
    // Tracked ALU Helpers (Batch-Mode Optimized)
    // ========================================================================

    #[inline(always)]
    pub fn adi_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let base = self.read_reg_b_tracked(rs1);
        let v = base.wrapping_add(sign_extend_imm32(imm));
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn adr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_add(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sbi_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b_tracked(rs1)
            .wrapping_sub(sign_extend_imm32(imm));
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sbr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_sub(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn addw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value = u64::from(
            (self.read_reg_b_tracked(rs1) as u32).wrapping_add(self.read_reg_c_tracked(rs2) as u32),
        );
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn subw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value = u64::from(
            (self.read_reg_b_tracked(rs1) as u32).wrapping_sub(self.read_reg_c_tracked(rs2) as u32),
        );
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sllw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c_tracked(rs2));
        let value = u64::from((self.read_reg_b_tracked(rs1) as u32).wrapping_shl(shamt));
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn srlw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c_tracked(rs2));
        let value = u64::from((self.read_reg_b_tracked(rs1) as u32).wrapping_shr(shamt));
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sraw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c_tracked(rs2));
        let value = (self.read_reg_b_tracked(rs1) as u32 as i32).wrapping_shr(shamt);
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn xri_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1) ^ sign_extend_imm32(imm);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn xrr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1 ^ v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn ori_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1) | sign_extend_imm32(imm);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn orr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1 | v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn ani_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1) & sign_extend_imm32(imm);
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn anr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1 & v2);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sli_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b_tracked(rs1)
            .wrapping_shl(Self::shift_u32(imm));
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn slr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_shl(Self::shift_u32(v2)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sri_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b_tracked(rs1)
            .wrapping_shr(Self::shift_u32(imm));
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn srr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_shr(Self::shift_u32(v2)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sai_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = (self.read_reg_b_tracked(rs1) as i64).wrapping_shr(Self::shift_u32(imm));
        self.write_reg_tracked(rd, v as u64);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sar_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let value = (v1 as i64).wrapping_shr(Self::shift_u32(v2));
        self.write_reg_tracked(rd, value as u64);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn slti_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1);
        let result = if (v as i64) < (sign_extend_imm32(imm) as i64) {
            1
        } else {
            0
        };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sltr_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if (v1 as i64) < (v2 as i64) { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sltiu_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b_tracked(rs1);
        let imm = sign_extend_imm32(imm);
        let result = if v < imm { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn sltru_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let result = if v1 < v2 { 1 } else { 0 };
        self.write_reg_tracked(rd, result);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline(always)]
    pub fn apc_tracked(&mut self, rd: usize, pc: u64, imm: u64, next_pc: u64) {
        self.write_reg_tracked(rd, pc.wrapping_add(sign_extend_imm32(imm)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn lw_tracked(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let base = self.read_reg_b_tracked(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(4) {
            return Err(format!("Unaligned LW at {:#x}", addr));
        }
        let v = self.read_mem_word(addr);
        self.write_reg_tracked(rd, (v as u32 as i32) as i64 as u64);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn lwu_tracked(
        &mut self,
        rd: usize,
        rs1: usize,
        imm: u64,
        next_pc: u64,
    ) -> Result<(), String> {
        let base = self.read_reg_b_tracked(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(4) {
            return Err(format!("Unaligned LWU at {:#x}", addr));
        }
        let value = self.read_mem_word(addr);
        self.write_reg_tracked(rd, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn ld_tracked(
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
        let value = self.read_mem_dword(addr);
        self.write_reg_tracked(rd, value);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn sw_tracked(
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
        if !addr.is_multiple_of(4) {
            return Err(format!("Unaligned SW at {:#x}", addr));
        }
        self.write_mem_word(addr, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn sd_tracked(
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
        self.write_mem_dword(addr, v);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn mulw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value = u64::from(
            (self.read_reg_b_tracked(rs1) as u32).wrapping_mul(self.read_reg_c_tracked(rs2) as u32),
        );
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn divw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32 as i32;
        let rhs = self.read_reg_c_tracked(rs2) as u32 as i32;
        let value = if rhs == 0 {
            -1i32
        } else if lhs == i32::MIN && rhs == -1 {
            i32::MIN
        } else {
            lhs.wrapping_div(rhs)
        };
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn divuw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32;
        let rhs = self.read_reg_c_tracked(rs2) as u32;
        let value = if rhs == 0 {
            u32::MAX
        } else {
            lhs.wrapping_div(rhs)
        };
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(u64::from(value)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn remw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32 as i32;
        let rhs = self.read_reg_c_tracked(rs2) as u32 as i32;
        let value = if rhs == 0 {
            lhs
        } else if lhs == i32::MIN && rhs == -1 {
            0
        } else {
            lhs.wrapping_rem(rhs)
        };
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn remuw_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b_tracked(rs1) as u32;
        let rhs = self.read_reg_c_tracked(rs2) as u32;
        let value = if rhs == 0 { lhs } else { lhs.wrapping_rem(rhs) };
        self.write_reg_tracked(rd, Self::sign_extend_word_result_u64(u64::from(value)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn lh_tracked(
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
        let word = self.read_mem_dword(Self::dword_addr(addr));
        let v = Self::read_u16_from_word(word, addr);
        self.write_reg_tracked(rd, (v as i16) as i64 as u64);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn lhu_tracked(
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
        let word = self.read_mem_dword(Self::dword_addr(addr));
        self.write_reg_tracked(rd, u64::from(Self::read_u16_from_word(word, addr)));
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn sh_tracked(
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
        let word_addr = Self::dword_addr(addr);
        let word = self.read_mem_dword(word_addr);
        let new_word = Self::write_u16_into_word(word, addr, v);
        self.write_mem_dword(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
        Ok(())
    }

    #[inline]
    pub fn lb_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        let word = self.read_mem_dword(Self::dword_addr(addr));
        let v = Self::read_u8_from_word(word, addr) as i8 as i64 as u64;
        self.write_reg_tracked(rd, v);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn lbu_tracked(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        let word = self.read_mem_dword(Self::dword_addr(addr));
        self.write_reg_tracked(rd, u64::from(Self::read_u8_from_word(word, addr)));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn sb_tracked(&mut self, rs2: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_a_tracked(rs2);
        let addr = self
            .read_reg_b_tracked(rs1)
            .wrapping_add(sign_extend_imm32(imm));
        let word_addr = Self::dword_addr(addr);
        let word = self.read_mem_dword(word_addr);
        let new_word = Self::write_u8_into_word(word, addr, v);
        self.write_mem_dword(word_addr, new_word);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn mul_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, v1.wrapping_mul(v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn mulh_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, Self::rv64_mulh_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn mulhu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, Self::rv64_mulhu_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn mulhsu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        self.write_reg_tracked(rd, Self::rv64_mulhsu_result_u64(v1, v2));
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn div_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = Self::rv64_div_result_u64(v1, v2);
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn divu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = Self::rv64_divu_result_u64(v1, v2);
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn rem_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = Self::rv64_rem_result_u64(v1, v2);
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }

    #[inline]
    pub fn remu_tracked(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c_tracked(rs2);
        let v1 = self.read_reg_b_tracked(rs1);
        let rv = Self::rv64_remu_result_u64(v1, v2);
        self.write_reg_tracked(rd, rv);
        self.pc = next_pc;
        self.update_insn_clock();
    }
}
