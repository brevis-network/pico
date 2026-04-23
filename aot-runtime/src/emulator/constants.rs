// Constants for instruction encoding
pub const SHIFT_MASK: u32 = 0x3f; // Mask for RV64 shift amounts (6 bits)
pub const BYTES_PER_WORD: u32 = 4;
pub const CLOCK_INCREMENT_PER_INSN: u32 = 4;

#[inline(always)]
pub const fn sign_extend_imm32(imm: u64) -> u64 {
    // Centralized RV64 sign-extension for decoded immediates stored in the low 32 bits.
    (imm as u32 as i32 as i64) as u64
}
