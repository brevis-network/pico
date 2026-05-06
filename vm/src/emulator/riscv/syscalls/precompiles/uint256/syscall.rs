use num::{BigUint, One, Zero};

use crate::{
    chips::{
        gadgets::utils::conversions::bytes_to_words_le, precompiles::uint256::UINT256_NUM_WORDS,
    },
    emulator::riscv::{
        event_types::RvValue,
        syscalls::{
            precompiles::{PrecompileEvent, Uint256MulEvent},
            syscall_context::SyscallContext,
            Syscall, SyscallCode,
        },
    },
};

pub(crate) struct Uint256MulSyscall;

impl Syscall for Uint256MulSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let clk = ctx.clk;

        let x_ptr = arg1;
        SyscallContext::assert_dword_aligned_precompile(x_ptr, "uint256 x_ptr");
        let y_ptr = arg2;
        SyscallContext::assert_dword_aligned_precompile(y_ptr, "uint256 y_ptr");

        // First read the words for the x value. We can read a slice_unsafe here because we write
        // the computed result to x later.
        // The legacy uint256 chip contract counts eight 32-bit words, but the RV64 guest ABI
        // stores the same 256-bit value as four packed 64-bit dwords in memory.
        let num_memory_words = UINT256_NUM_WORDS;
        let x_vals = ctx.dword_slice_unsafe(x_ptr, num_memory_words);

        // Read the y value.
        let (y_memory_records, y_vals) = ctx.mr_dword_slice(y_ptr, num_memory_words);

        // The modulus is stored after the y value. We increment the pointer by the number of words.
        // `y` occupies `num_memory_words` packed dwords, so the modulus starts `8 * N` bytes later.
        let modulus_ptr = y_ptr + (num_memory_words as u64) * 8;
        let (modulus_memory_records, modulus_vals) =
            ctx.mr_dword_slice(modulus_ptr, num_memory_words);

        // Get the BigUint values for x, y, and the modulus.
        let uint256_x = BigUint::from_bytes_le(
            &x_vals
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        let uint256_y = BigUint::from_bytes_le(
            &y_vals
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>(),
        );
        let uint256_modulus = BigUint::from_bytes_le(
            &modulus_vals
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>(),
        );

        // Perform the multiplication and take the result modulo the modulus.
        let result: BigUint = if uint256_modulus.is_zero() {
            let modulus = BigUint::one() << 256;
            (uint256_x * uint256_y) % modulus
        } else {
            (uint256_x * uint256_y) % uint256_modulus
        };

        let mut result_bytes = result.to_bytes_le();
        result_bytes.resize(32, 0u8); // Pad the result to 32 bytes.

        // Convert the result to four packed little-endian u64 words.
        let result = bytes_to_words_le::<8>(&result_bytes);
        let result_u64: Vec<u64> = result
            .chunks_exact(2)
            .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
            .collect();

        // Increment clk so that the write is not at the same cycle as the read.
        ctx.clk += 1;
        // Write the result to x and keep track of the memory records.
        let x_memory_records = ctx.mw_dword_slice(x_ptr, &result_u64);

        let chunk = ctx.current_chunk();

        let event = PrecompileEvent::Uint256Mul(Uint256MulEvent {
            chunk,
            clk,
            x_ptr,
            x: x_vals.try_into().unwrap(),
            y_ptr,
            y: y_vals.try_into().unwrap(),
            modulus: modulus_vals.try_into().unwrap(),
            x_memory_records: x_memory_records.try_into().unwrap(),
            y_memory_records: y_memory_records.try_into().unwrap(),
            modulus_memory_records: modulus_memory_records.try_into().unwrap(),
            local_mem_access: ctx.postprocess(),
        });

        let syscall_event = ctx
            .rt
            .syscall_event(clk, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut()
            .add_precompile_event(syscall_code, syscall_event, event);

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
