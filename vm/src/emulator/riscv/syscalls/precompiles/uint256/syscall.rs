use num::{BigUint, One, Zero};

use crate::{
    chips::{
        gadgets::utils::conversions::{bytes_to_words_le, words_to_bytes_le_vec},
        precompiles::uint256::UINT256_NUM_WORDS,
    },
    emulator::riscv::syscalls::{
        precompiles::uint256::event::Uint256MulEvent, syscall_context::SyscallContext, Syscall,
        SyscallCode,
    },
    primitives::consts::WORD_SIZE,
};

pub(crate) struct Uint256MulSyscall;

impl Syscall for Uint256MulSyscall {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        _syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let clk = ctx.clk;

        let x_ptr = arg1;
        if x_ptr % 4 != 0 {
            panic!();
        }
        let y_ptr = arg2;
        if y_ptr % 4 != 0 {
            panic!();
        }

        // First read the words for the x value. We can read a slice_unsafe here because we write
        // the computed result to x later.
        let x = ctx.slice_unsafe(x_ptr, UINT256_NUM_WORDS);

        // Read the y value.
        let (y_memory_records, y) = ctx.mr_slice(y_ptr, UINT256_NUM_WORDS);

        // The modulus is stored after the y value. We increment the pointer by the number of words.
        let modulus_ptr = y_ptr + UINT256_NUM_WORDS as u32 * WORD_SIZE as u32;
        let (modulus_memory_records, modulus) = ctx.mr_slice(modulus_ptr, UINT256_NUM_WORDS);

        // Get the BigUint values for x, y, and the modulus.
        let uint256_x = BigUint::from_bytes_le(&words_to_bytes_le_vec(&x));
        let uint256_y = BigUint::from_bytes_le(&words_to_bytes_le_vec(&y));
        let uint256_modulus = BigUint::from_bytes_le(&words_to_bytes_le_vec(&modulus));

        // Perform the multiplication and take the result modulo the modulus.
        let result: BigUint = if uint256_modulus.is_zero() {
            let modulus = BigUint::one() << 256;
            (uint256_x * uint256_y) % modulus
        } else {
            (uint256_x * uint256_y) % uint256_modulus
        };

        let mut result_bytes = result.to_bytes_le();
        result_bytes.resize(32, 0u8); // Pad the result to 32 bytes.

        // Convert the result to little endian u32 words.
        let result = bytes_to_words_le::<8>(&result_bytes);

        // Increment clk so that the write is not at the same cycle as the read.
        ctx.clk += 1;
        // Write the result to x and keep track of the memory records.
        let x_memory_records = ctx.mw_slice(x_ptr, &result);

        let lookup_id = ctx.syscall_lookup_id;
        let chunk = ctx.current_chunk();

        // Todo: Add local_mem_access after scope update
        let event = Uint256MulEvent {
            lookup_id,
            chunk,
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            modulus,
            x_memory_records,
            y_memory_records,
            modulus_memory_records,
        };

        ctx.record_mut().add_uint256_mul_event(event);

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
