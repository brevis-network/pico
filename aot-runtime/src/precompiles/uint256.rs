use crate::{
    emulator::AotEmulatorCore,
    precompiles::limb_math::{uint256_mod_mul, Limbs8},
};
use pico_vm::chips::{
    gadgets::utils::conversions::bytes_to_words_le, precompiles::uint256::UINT256_NUM_WORDS,
};

/// UINT256 multiply syscall implementation.
#[inline(always)]
pub fn uint256_mul(core: &mut AotEmulatorCore, x_ptr: u64, y_ptr: u64) {
    assert!(x_ptr.is_multiple_of(8), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(8), "y_ptr is unaligned");

    let clk = core.clk;
    let num_dwords = UINT256_NUM_WORDS;

    // Stack-allocated packed-dword buffers (4 dwords each = 32 bytes).
    let mut x = [0u64; UINT256_NUM_WORDS];
    let mut y = [0u64; UINT256_NUM_WORDS];
    let mut modulus = [0u64; UINT256_NUM_WORDS];

    core.read_mem_dword_span_snapshot(x_ptr, &mut x);
    core.read_mem_dword_span_at_clk(y_ptr, &mut y, clk);

    // The modulus is stored after the y value
    let modulus_ptr = y_ptr + (num_dwords as u64) * 8;
    core.read_mem_dword_span_at_clk(modulus_ptr, &mut modulus, clk);

    let x_words = packed_dwords_to_u32_words(&x);
    let y_words = packed_dwords_to_u32_words(&y);
    let modulus_words = packed_dwords_to_u32_words(&modulus);
    let x_limbs = Limbs8::from_slice(&x_words);
    let y_limbs = Limbs8::from_slice(&y_words);
    let modulus_limbs = Limbs8::from_slice(&modulus_words);

    // Perform uint256 modular multiplication
    let result = uint256_mod_mul(&x_limbs, &y_limbs, &modulus_limbs);

    let result_dwords = u32_words_to_packed_dwords(&result.limbs);
    core.write_mem_dword_span_at_clk(x_ptr, &result_dwords, clk + 1);
}

fn packed_dwords_to_u32_words(values: &[u64]) -> [u32; UINT256_NUM_WORDS * 2] {
    let mut words = [0u32; UINT256_NUM_WORDS * 2];
    for (index, value) in values.iter().copied().enumerate() {
        words[index * 2] = value as u32;
        words[index * 2 + 1] = (value >> 32) as u32;
    }
    words
}

fn u32_words_to_packed_dwords(words: &[u32; UINT256_NUM_WORDS * 2]) -> [u64; UINT256_NUM_WORDS] {
    let result = bytes_to_words_le::<8>(
        &words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    let mut dwords = [0u64; UINT256_NUM_WORDS];
    for (index, pair) in result.chunks_exact(2).enumerate() {
        dwords[index] = u64::from(pair[0]) | (u64::from(pair[1]) << 32);
    }
    dwords
}

#[cfg(test)]
mod tests {
    use super::{packed_dwords_to_u32_words, u32_words_to_packed_dwords};

    #[test]
    fn phase5_uint256_packed_dword_round_trip() {
        let words = [
            0x0001_0002,
            0x0003_0004,
            0x1111_2222,
            0x3333_4444,
            0x5555_6666,
            0x7777_8888,
            0x9999_aaaa,
            0xbbbb_cccc,
        ];

        let dwords = u32_words_to_packed_dwords(&words);
        assert_eq!(dwords[0], 0x0003_0004_0001_0002);
        assert_eq!(packed_dwords_to_u32_words(&dwords), words);
    }
}
