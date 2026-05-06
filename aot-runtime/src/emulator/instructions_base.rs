use super::{
    constants::{sign_extend_imm32, BYTES_PER_WORD, SHIFT_MASK},
    AotEmulatorCore,
};

impl AotEmulatorCore {
    #[inline(always)]
    pub(crate) fn shift_amount_u32(value: u64) -> u32 {
        (value & u64::from(SHIFT_MASK)) as u32
    }

    #[inline(always)]
    pub fn sign_extend_word_result_u64(value: u64) -> u64 {
        (value as u32 as i32 as i64) as u64
    }

    #[inline(always)]
    pub fn word_shift_amount_u32(value: u64) -> u32 {
        (value & 0x1f) as u32
    }

    #[inline(always)]
    pub(crate) fn rv64_mulh_result_u64(lhs: u64, rhs: u64) -> u64 {
        (((lhs as i64) as i128).wrapping_mul((rhs as i64) as i128) >> 64) as u64
    }

    #[inline(always)]
    pub(crate) fn rv64_mulhu_result_u64(lhs: u64, rhs: u64) -> u64 {
        ((lhs as u128).wrapping_mul(rhs as u128) >> 64) as u64
    }

    #[inline(always)]
    pub(crate) fn rv64_mulhsu_result_u64(lhs: u64, rhs: u64) -> u64 {
        (((lhs as i64) as i128).wrapping_mul(rhs as i128) >> 64) as u64
    }

    #[inline(always)]
    pub(crate) fn rv64_div_result_u64(lhs: u64, rhs: u64) -> u64 {
        let lhs = lhs as i64;
        let rhs = rhs as i64;
        if rhs == 0 {
            u64::MAX
        } else if lhs == i64::MIN && rhs == -1 {
            i64::MIN as u64
        } else {
            lhs.wrapping_div(rhs) as u64
        }
    }

    #[inline(always)]
    pub(crate) fn rv64_divu_result_u64(lhs: u64, rhs: u64) -> u64 {
        if rhs == 0 {
            u64::MAX
        } else {
            lhs.wrapping_div(rhs)
        }
    }

    #[inline(always)]
    pub(crate) fn rv64_rem_result_u64(lhs: u64, rhs: u64) -> u64 {
        let lhs = lhs as i64;
        let rhs = rhs as i64;
        if rhs == 0 {
            lhs as u64
        } else if lhs == i64::MIN && rhs == -1 {
            0
        } else {
            lhs.wrapping_rem(rhs) as u64
        }
    }

    #[inline(always)]
    pub(crate) fn rv64_remu_result_u64(lhs: u64, rhs: u64) -> u64 {
        if rhs == 0 {
            lhs
        } else {
            lhs.wrapping_rem(rhs)
        }
    }

    // ========================================================================
    // Instruction Helpers (AOT Code Size Reduction)
    // ========================================================================
    //
    // These inline helpers reduce generated code size by factoring out common
    // instruction patterns into single function calls. They are used by the
    // AOT code generator to produce more compact generated code.
    // ========================================================================

    /// ALU immediate add: rd = rs1 + imm; pc = next_pc
    #[inline(always)]
    pub fn adi(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let base = self.read_reg_b(rs1);
        let v = base.wrapping_add(sign_extend_imm32(imm));
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU immediate sub: rd = rs1 - imm; pc = next_pc
    #[inline(always)]
    pub fn sbi(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b(rs1).wrapping_sub(sign_extend_imm32(imm));
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register add: rd = rs1 + rs2; pc = next_pc
    #[inline(always)]
    pub fn adr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_add(v2));
        self.pc = next_pc;
    }

    /// ALU register sub: rd = rs1 - rs2; pc = next_pc
    #[inline(always)]
    pub fn sbr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_sub(v2));
        self.pc = next_pc;
    }

    #[inline(always)]
    pub fn addw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value =
            u64::from((self.read_reg_b(rs1) as u32).wrapping_add(self.read_reg_c(rs2) as u32));
        self.write_reg(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
    }

    #[inline(always)]
    pub fn subw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value =
            u64::from((self.read_reg_b(rs1) as u32).wrapping_sub(self.read_reg_c(rs2) as u32));
        self.write_reg(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
    }

    #[inline(always)]
    pub fn sllw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c(rs2));
        let value = u64::from((self.read_reg_b(rs1) as u32).wrapping_shl(shamt));
        self.write_reg(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
    }

    #[inline(always)]
    pub fn srlw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c(rs2));
        let value = u64::from((self.read_reg_b(rs1) as u32).wrapping_shr(shamt));
        self.write_reg(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
    }

    #[inline(always)]
    pub fn sraw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let shamt = Self::word_shift_amount_u32(self.read_reg_c(rs2));
        let value = (self.read_reg_b(rs1) as u32 as i32).wrapping_shr(shamt);
        self.write_reg(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
    }

    /// ALU immediate xor: rd = rs1 ^ imm; pc = next_pc
    #[inline(always)]
    pub fn xri(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b(rs1) ^ sign_extend_imm32(imm);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register xor: rd = rs1 ^ rs2; pc = next_pc
    #[inline(always)]
    pub fn xrr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1 ^ v2);
        self.pc = next_pc;
    }

    /// ALU immediate or: rd = rs1 | imm; pc = next_pc
    #[inline(always)]
    pub fn ori(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b(rs1) | sign_extend_imm32(imm);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register or: rd = rs1 | rs2; pc = next_pc
    #[inline(always)]
    pub fn orr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1 | v2);
        self.pc = next_pc;
    }

    /// ALU immediate and: rd = rs1 & imm; pc = next_pc
    #[inline(always)]
    pub fn ani(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b(rs1) & sign_extend_imm32(imm);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register and: rd = rs1 & rs2; pc = next_pc
    #[inline(always)]
    pub fn anr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1 & v2);
        self.pc = next_pc;
    }

    /// Shift left logical immediate: rd = rs1 << (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sli(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b(rs1)
            .wrapping_shl(Self::shift_amount_u32(imm));
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Shift left logical register: rd = rs1 << (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn slr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_shl(Self::shift_amount_u32(v2)));
        self.pc = next_pc;
    }

    /// Shift right logical immediate: rd = rs1 >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sri(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self
            .read_reg_b(rs1)
            .wrapping_shr(Self::shift_amount_u32(imm));
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Shift right logical register: rd = rs1 >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn srr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_shr(Self::shift_amount_u32(v2)));
        self.pc = next_pc;
    }

    /// Shift right arithmetic immediate: rd = (rs1 as i64) >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sai(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = (self.read_reg_b(rs1) as i64).wrapping_shr(Self::shift_amount_u32(imm));
        self.write_reg(rd, v as u64);
        self.pc = next_pc;
    }

    /// Shift right arithmetic register: rd = (rs1 as i64) >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sar(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(
            rd,
            (v1 as i64).wrapping_shr(Self::shift_amount_u32(v2)) as u64,
        );
        self.pc = next_pc;
    }

    /// Set less than immediate (signed): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn slti(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b(rs1) as i64;
        self.write_reg(
            rd,
            if v < (sign_extend_imm32(imm) as i64) {
                1
            } else {
                0
            },
        );
        self.pc = next_pc;
    }

    /// Set less than register (signed): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2) as i64;
        let v1 = self.read_reg_b(rs1) as i64;
        self.write_reg(rd, if v1 < v2 { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// Set less than immediate (unsigned): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltiu(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_b(rs1);
        let imm = sign_extend_imm32(imm);
        self.write_reg(rd, if v < imm { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// Set less than register (unsigned): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltru(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, if v1 < v2 { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// AUIPC: rd = pc + imm; next_pc
    #[inline(always)]
    pub fn apc(&mut self, rd: usize, pc: u64, imm: u64, next_pc: u64) {
        self.write_reg(rd, pc.wrapping_add(sign_extend_imm32(imm)));
        self.pc = next_pc;
    }

    /// Load word: rd = mem[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn lw(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let base = self.read_reg_b(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned LW at {:#x}", addr));
        }
        let v = self.read_mem_word(addr);
        self.write_reg(rd, (v as u32 as i32) as i64 as u64);
        self.pc = next_pc;
        Ok(())
    }

    /// Load word unsigned: rd = zero_ext(mem_word[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lwu(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let base = self.read_reg_b(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned LWU at {:#x}", addr));
        }
        let value = self.read_mem_word(addr);
        self.write_reg(rd, value);
        self.pc = next_pc;
        Ok(())
    }

    /// Load doubleword: rd = mem_dword[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn ld(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let base = self.read_reg_b(rs1);
        let addr = base.wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(8) {
            return Err(format!("Unaligned LD at {:#x}", addr));
        }
        let value = self.read_mem_dword(addr);
        self.write_reg(rd, value);
        self.pc = next_pc;
        Ok(())
    }

    /// Store word: mem[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sw(&mut self, rs2: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(u64::from(BYTES_PER_WORD)) {
            return Err(format!("Unaligned SW at {:#x}", addr));
        }
        self.write_mem_word(addr, v);
        self.pc = next_pc;
        Ok(())
    }

    /// Store doubleword: mem_dword[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sd(&mut self, rs2: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(8) {
            return Err(format!("Unaligned SD at {:#x}", addr));
        }
        self.write_mem_dword(addr, v);
        self.pc = next_pc;
        Ok(())
    }

    #[inline]
    pub fn mulw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let value =
            u64::from((self.read_reg_b(rs1) as u32).wrapping_mul(self.read_reg_c(rs2) as u32));
        self.write_reg(rd, Self::sign_extend_word_result_u64(value));
        self.pc = next_pc;
    }

    #[inline]
    pub fn divw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b(rs1) as u32 as i32;
        let rhs = self.read_reg_c(rs2) as u32 as i32;
        let value = if rhs == 0 {
            -1i32
        } else if lhs == i32::MIN && rhs == -1 {
            i32::MIN
        } else {
            lhs.wrapping_div(rhs)
        };
        self.write_reg(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
    }

    #[inline]
    pub fn divuw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b(rs1) as u32;
        let rhs = self.read_reg_c(rs2) as u32;
        let value = if rhs == 0 {
            u32::MAX
        } else {
            lhs.wrapping_div(rhs)
        };
        self.write_reg(rd, Self::sign_extend_word_result_u64(u64::from(value)));
        self.pc = next_pc;
    }

    #[inline]
    pub fn remw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b(rs1) as u32 as i32;
        let rhs = self.read_reg_c(rs2) as u32 as i32;
        let value = if rhs == 0 {
            lhs
        } else if lhs == i32::MIN && rhs == -1 {
            0
        } else {
            lhs.wrapping_rem(rhs)
        };
        self.write_reg(rd, Self::sign_extend_word_result_u64(value as u32 as u64));
        self.pc = next_pc;
    }

    #[inline]
    pub fn remuw(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let lhs = self.read_reg_b(rs1) as u32;
        let rhs = self.read_reg_c(rs2) as u32;
        let value = if rhs == 0 { lhs } else { lhs.wrapping_rem(rhs) };
        self.write_reg(rd, Self::sign_extend_word_result_u64(u64::from(value)));
        self.pc = next_pc;
    }

    /// Load half signed: rd = sign_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lh(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LH at {:#x}", addr));
        }
        let word = self.read_mem_dword(Self::dword_addr(addr));
        let v = Self::read_u16_from_word(word, addr);
        self.write_reg(rd, (v as i16) as i64 as u64);
        self.pc = next_pc;
        Ok(())
    }

    /// Load half unsigned: rd = zero_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lhu(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LHU at {:#x}", addr));
        }
        let word = self.read_mem_dword(Self::dword_addr(addr));
        self.write_reg(rd, u64::from(Self::read_u16_from_word(word, addr)));
        self.pc = next_pc;
        Ok(())
    }

    /// Store half: mem_half[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sh(&mut self, rs2: usize, rs1: usize, imm: u64, next_pc: u64) -> Result<(), String> {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned SH at {:#x}", addr));
        }
        let word_addr = Self::dword_addr(addr);
        let word = self.read_mem_dword(word_addr);
        let new_word = Self::write_u16_into_word(word, addr, v);
        self.write_mem_dword(word_addr, new_word);
        self.pc = next_pc;
        Ok(())
    }

    /// Load byte signed: rd = sign_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lb(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        let word = self.read_mem_dword(Self::dword_addr(addr));
        let v = Self::read_u8_from_word(word, addr) as i8 as i64 as u64;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Load byte unsigned: rd = zero_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lbu(&mut self, rd: usize, rs1: usize, imm: u64, next_pc: u64) {
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        let word = self.read_mem_dword(Self::dword_addr(addr));
        let v = u64::from(Self::read_u8_from_word(word, addr));
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Store byte: mem_byte[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sb(&mut self, rs2: usize, rs1: usize, imm: u64, next_pc: u64) {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(sign_extend_imm32(imm));
        let word_addr = Self::dword_addr(addr);
        let word = self.read_mem_dword(word_addr);
        let new_word = Self::write_u8_into_word(word, addr, v);
        self.write_mem_dword(word_addr, new_word);
        self.pc = next_pc;
    }

    /// Multiply: rd = rs1 * rs2; pc = next_pc
    #[inline]
    pub fn mul(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_mul(v2));
        self.pc = next_pc;
    }

    /// Multiply high signed-signed: rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline]
    pub fn mulh(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, Self::rv64_mulh_result_u64(v1, v2));
        self.pc = next_pc;
    }

    /// Multiply high unsigned-unsigned: rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline]
    pub fn mulhu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, Self::rv64_mulhu_result_u64(v1, v2));
        self.pc = next_pc;
    }

    /// Multiply high signed-unsigned: rd = (rs1 * rs2) >> 64; pc = next_pc
    #[inline]
    pub fn mulhsu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, Self::rv64_mulhsu_result_u64(v1, v2));
        self.pc = next_pc;
    }

    /// Divide signed: rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn div(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        let rv = Self::rv64_div_result_u64(v1, v2);
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }

    /// Divide unsigned: rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn divu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        let rv = Self::rv64_divu_result_u64(v1, v2);
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }

    /// Remainder signed: rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn rem(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        let rv = Self::rv64_rem_result_u64(v1, v2);
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }

    /// Remainder unsigned: rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn remu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u64) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        let rv = Self::rv64_remu_result_u64(v1, v2);
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }
}

#[cfg(test)]
mod tests {
    use super::AotEmulatorCore;

    #[test]
    fn rv64_mul_high_helpers_match_riscv64_semantics() {
        assert_eq!(
            AotEmulatorCore::rv64_mulh_result_u64(0xffff_ffff_ffff_fffe, 0x88),
            0xffff_ffff_ffff_ffff
        );
        assert_eq!(
            AotEmulatorCore::rv64_mulhu_result_u64(0xffff_ffff_ffff_fffe, 0x88),
            0x87
        );
        assert_eq!(
            AotEmulatorCore::rv64_mulhsu_result_u64(0xffff_ffff_ffff_fffe, 0x88),
            0xffff_ffff_ffff_ffff
        );
    }

    #[test]
    fn rv64_div_rem_helpers_match_riscv64_semantics() {
        assert_eq!(AotEmulatorCore::rv64_div_result_u64(u64::MAX, 2), 0);
        assert_eq!(
            AotEmulatorCore::rv64_div_result_u64(i64::MIN as u64, (-1i64) as u64),
            i64::MIN as u64
        );
        assert_eq!(AotEmulatorCore::rv64_divu_result_u64(7, 0), u64::MAX);
        assert_eq!(
            AotEmulatorCore::rv64_rem_result_u64(i64::MIN as u64, (-1i64) as u64),
            0
        );
        assert_eq!(
            AotEmulatorCore::rv64_rem_result_u64((-9i64) as u64, 4),
            (-1i64) as u64
        );
        assert_eq!(AotEmulatorCore::rv64_remu_result_u64(9, 4), 1);
    }
}
