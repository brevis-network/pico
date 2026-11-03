use super::{constants::SHIFT_MASK, AotEmulatorCore};

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
