use crate::emulator::riscv::event_types::RvValue;

#[inline(always)]
pub(crate) fn decode_u32_abi_word(arg: RvValue, context: &str) -> u32 {
    let low = arg as u32;
    let zero_ext = u64::from(low);
    let sign_ext = (low as i32 as i64) as u64;

    if arg == zero_ext || arg == sign_ext {
        low
    } else {
        panic!("{context} invalid 32-bit ABI encoding: 0x{arg:016x}");
    }
}

#[inline(always)]
pub(crate) fn decode_u32_abi_index(arg: RvValue, bound: usize, context: &str) -> usize {
    let low = arg as u32;
    let zero_ext = u64::from(low);

    if arg != zero_ext {
        panic!("{context} invalid unsigned index encoding: 0x{arg:016x}");
    }

    let index = usize::try_from(low).unwrap_or_else(|_| panic!("{context} index overflow: {arg}"));
    if index >= bound {
        panic!("{context} index out of range: {index} >= {bound}");
    }
    index
}

#[cfg(test)]
mod tests {
    use super::{decode_u32_abi_index, decode_u32_abi_word};

    #[test]
    fn accepts_zero_and_sign_extended_u32_words() {
        assert_eq!(decode_u32_abi_word(7, "test"), 7);
        assert_eq!(decode_u32_abi_word(0xffff_ffff, "test"), u32::MAX);
        assert_eq!(decode_u32_abi_word(0xffff_ffff_ffff_ffff, "test"), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "invalid 32-bit ABI encoding")]
    fn rejects_non_abi_encoded_words() {
        decode_u32_abi_word(0x0000_0001_0000_0000, "test");
    }

    #[test]
    fn accepts_zero_extended_indices_in_range() {
        assert_eq!(decode_u32_abi_index(0, 8, "test"), 0);
        assert_eq!(decode_u32_abi_index(7, 8, "test"), 7);
    }

    #[test]
    #[should_panic(expected = "invalid unsigned index encoding")]
    fn rejects_sign_extended_indices() {
        decode_u32_abi_index(0xffff_ffff_ffff_ffff, 8, "test");
    }

    #[test]
    #[should_panic(expected = "index out of range")]
    fn rejects_out_of_range_indices() {
        decode_u32_abi_index(8, 8, "test");
    }
}
