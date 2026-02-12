use super::{
    constants::{BYTES_PER_WORD, SHIFT_MASK},
    AotEmulatorCore,
};

impl AotEmulatorCore {
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
    pub fn adi(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let base = self.read_reg_b(rs1);
        let v = base.wrapping_add(imm);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU immediate sub: rd = rs1 - imm; pc = next_pc
    #[inline(always)]
    pub fn sbi(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1).wrapping_sub(imm);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register add: rd = rs1 + rs2; pc = next_pc
    #[inline(always)]
    pub fn adr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_add(v2));
        self.pc = next_pc;
    }

    /// ALU register sub: rd = rs1 - rs2; pc = next_pc
    #[inline(always)]
    pub fn sbr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_sub(v2));
        self.pc = next_pc;
    }

    /// ALU immediate xor: rd = rs1 ^ imm; pc = next_pc
    #[inline(always)]
    pub fn xri(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1) ^ imm;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register xor: rd = rs1 ^ rs2; pc = next_pc
    #[inline(always)]
    pub fn xrr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1 ^ v2);
        self.pc = next_pc;
    }

    /// ALU immediate or: rd = rs1 | imm; pc = next_pc
    #[inline(always)]
    pub fn ori(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1) | imm;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register or: rd = rs1 | rs2; pc = next_pc
    #[inline(always)]
    pub fn orr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1 | v2);
        self.pc = next_pc;
    }

    /// ALU immediate and: rd = rs1 & imm; pc = next_pc
    #[inline(always)]
    pub fn ani(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1) & imm;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// ALU register and: rd = rs1 & rs2; pc = next_pc
    #[inline(always)]
    pub fn anr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1 & v2);
        self.pc = next_pc;
    }

    /// Shift left logical immediate: rd = rs1 << (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sli(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1).wrapping_shl(imm & SHIFT_MASK);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Shift left logical register: rd = rs1 << (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn slr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_shl(v2 & SHIFT_MASK));
        self.pc = next_pc;
    }

    /// Shift right logical immediate: rd = rs1 >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sri(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1).wrapping_shr(imm & SHIFT_MASK);
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Shift right logical register: rd = rs1 >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn srr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_shr(v2 & SHIFT_MASK));
        self.pc = next_pc;
    }

    /// Shift right arithmetic immediate: rd = (rs1 as i32) >> (imm & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sai(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = (self.read_reg_b(rs1) as i32).wrapping_shr(imm & SHIFT_MASK) as u32;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Shift right arithmetic register: rd = (rs1 as i32) >> (rs2 & SHIFT_MASK); pc = next_pc
    #[inline(always)]
    pub fn sar(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, (v1 as i32).wrapping_shr(v2 & SHIFT_MASK) as u32);
        self.pc = next_pc;
    }

    /// Set less than immediate (signed): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn slti(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1) as i32;
        self.write_reg(rd, if v < (imm as i32) { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// Set less than register (signed): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltr(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2) as i32;
        let v1 = self.read_reg_b(rs1) as i32;
        self.write_reg(rd, if v1 < v2 { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// Set less than immediate (unsigned): rd = (rs1 < imm) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltiu(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_b(rs1);
        self.write_reg(rd, if v < imm { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// Set less than register (unsigned): rd = (rs1 < rs2) ? 1 : 0; pc = next_pc
    #[inline(always)]
    pub fn sltru(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, if v1 < v2 { 1 } else { 0 });
        self.pc = next_pc;
    }

    /// AUIPC: rd = pc + imm; next_pc
    #[inline(always)]
    pub fn apc(&mut self, rd: usize, pc: u32, imm: u32, next_pc: u32) {
        self.write_reg(rd, pc.wrapping_add(imm));
        self.pc = next_pc;
    }

    /// Load word: rd = mem[rs1 + imm]; pc = next_pc
    #[inline]
    pub fn lw(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) -> Result<(), String> {
        let base = self.read_reg_b(rs1);
        let addr = base.wrapping_add(imm);
        if !addr.is_multiple_of(BYTES_PER_WORD) {
            return Err(format!("Unaligned LW at {:#x}", addr));
        }
        let v = self.read_mem(addr);
        self.write_reg(rd, v);
        self.pc = next_pc;
        Ok(())
    }

    /// Store word: mem[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sw(&mut self, rs2: usize, rs1: usize, imm: u32, next_pc: u32) -> Result<(), String> {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(BYTES_PER_WORD) {
            return Err(format!("Unaligned SW at {:#x}", addr));
        }
        self.write_mem(addr, v);
        self.pc = next_pc;
        Ok(())
    }

    /// Load half signed: rd = sign_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lh(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) -> Result<(), String> {
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LH at {:#x}", addr));
        }
        let word = self.read_mem(addr & !3);
        let v = if (addr >> 1).is_multiple_of(2) {
            word & 0xFFFF
        } else {
            (word >> 16) & 0xFFFF
        };
        self.write_reg(rd, ((v as i16) as i32) as u32);
        self.pc = next_pc;
        Ok(())
    }

    /// Load half unsigned: rd = zero_ext(mem_half[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lhu(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) -> Result<(), String> {
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
        if !addr.is_multiple_of(2) {
            return Err(format!("Unaligned LHU at {:#x}", addr));
        }
        let word = self.read_mem(addr & !3);
        let v = if (addr >> 1).is_multiple_of(2) {
            word & 0xFFFF
        } else {
            (word >> 16) & 0xFFFF
        };
        self.write_reg(rd, v);
        self.pc = next_pc;
        Ok(())
    }

    /// Store half: mem_half[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sh(&mut self, rs2: usize, rs1: usize, imm: u32, next_pc: u32) -> Result<(), String> {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
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
        Ok(())
    }

    /// Load byte signed: rd = sign_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lb(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
        let word = self.read_mem(addr & !(BYTES_PER_WORD - 1));
        let byte_idx = (addr % BYTES_PER_WORD) as usize;
        let v = (word.to_le_bytes()[byte_idx] as i8) as i32 as u32;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Load byte unsigned: rd = zero_ext(mem_byte[rs1 + imm]); pc = next_pc
    #[inline]
    pub fn lbu(&mut self, rd: usize, rs1: usize, imm: u32, next_pc: u32) {
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
        let word = self.read_mem(addr & !(BYTES_PER_WORD - 1));
        let byte_idx = (addr % BYTES_PER_WORD) as usize;
        let v = word.to_le_bytes()[byte_idx] as u32;
        self.write_reg(rd, v);
        self.pc = next_pc;
    }

    /// Store byte: mem_byte[rs1 + imm] = rs2; pc = next_pc
    #[inline]
    pub fn sb(&mut self, rs2: usize, rs1: usize, imm: u32, next_pc: u32) {
        let v = self.read_reg_a(rs2);
        let addr = self.read_reg_b(rs1).wrapping_add(imm);
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
    }

    /// Multiply: rd = rs1 * rs2; pc = next_pc
    #[inline]
    pub fn mul(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        self.write_reg(rd, v1.wrapping_mul(v2));
        self.pc = next_pc;
    }

    /// Multiply high signed-signed: rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulh(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2) as i32 as i64;
        let v1 = self.read_reg_b(rs1) as i32 as i64;
        self.write_reg(rd, (v1.wrapping_mul(v2) >> 32) as u32);
        self.pc = next_pc;
    }

    /// Multiply high unsigned-unsigned: rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulhu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2) as u64 as i64;
        let v1 = self.read_reg_b(rs1) as u64 as i64;
        self.write_reg(rd, (v1.wrapping_mul(v2) >> 32) as u32);
        self.pc = next_pc;
    }

    /// Multiply high signed-unsigned: rd = (rs1 * rs2) >> 32; pc = next_pc
    #[inline]
    pub fn mulhsu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2) as u64 as i64;
        let v1 = self.read_reg_b(rs1) as i32 as i64;
        self.write_reg(rd, (v1.wrapping_mul(v2) >> 32) as u32);
        self.pc = next_pc;
    }

    /// Divide signed: rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn div(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2) as i32;
        let v1 = self.read_reg_b(rs1) as i32;
        let rv = if v2 == 0 {
            u32::MAX
        } else {
            v1.wrapping_div(v2) as u32
        };
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }

    /// Divide unsigned: rd = rs1 / rs2; pc = next_pc
    #[inline]
    pub fn divu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        let rv = if v2 == 0 {
            u32::MAX
        } else {
            v1.wrapping_div(v2)
        };
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }

    /// Remainder signed: rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn rem(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2) as i32;
        let v1 = self.read_reg_b(rs1) as i32;
        let rv = if v2 == 0 { v1 } else { v1.wrapping_rem(v2) } as u32;
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }

    /// Remainder unsigned: rd = rs1 % rs2; pc = next_pc
    #[inline]
    pub fn remu(&mut self, rd: usize, rs1: usize, rs2: usize, next_pc: u32) {
        let v2 = self.read_reg_c(rs2);
        let v1 = self.read_reg_b(rs1);
        let rv = if v2 == 0 { v1 } else { v1.wrapping_rem(v2) };
        self.write_reg(rd, rv);
        self.pc = next_pc;
    }
}
