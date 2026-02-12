use crate::{
    emulator::AotEmulatorCore,
    precompiles::limb_math::{uint256_mod_mul, Limbs8},
};
use pico_vm::{chips::precompiles::uint256::UINT256_NUM_WORDS, primitives::consts::WORD_SIZE};

/// UINT256 multiply syscall implementation.
#[inline(always)]
pub fn uint256_mul(core: &mut AotEmulatorCore, x_ptr: u32, y_ptr: u32) {
    assert!(x_ptr.is_multiple_of(4), "x_ptr is unaligned");
    assert!(y_ptr.is_multiple_of(4), "y_ptr is unaligned");

    let clk = core.clk;

    // Stack-allocated buffers (8 words each = 32 bytes)
    let mut x = [0u32; UINT256_NUM_WORDS];
    let mut y = [0u32; UINT256_NUM_WORDS];
    let mut modulus = [0u32; UINT256_NUM_WORDS];

    // Read using span operations
    core.read_mem_span_snapshot(x_ptr, &mut x[..UINT256_NUM_WORDS]);
    core.read_mem_span_at_clk(y_ptr, &mut y, clk);

    // The modulus is stored after the y value
    let modulus_ptr = y_ptr + UINT256_NUM_WORDS as u32 * WORD_SIZE as u32;
    core.read_mem_span_at_clk(modulus_ptr, &mut modulus, clk);

    // Convert to limb representation
    let x_limbs = Limbs8::from_slice(&x);
    let y_limbs = Limbs8::from_slice(&y);
    let modulus_limbs = Limbs8::from_slice(&modulus);

    // Perform uint256 modular multiplication
    let result = uint256_mod_mul(&x_limbs, &y_limbs, &modulus_limbs);

    // Write the result to x using span operation.
    core.write_mem_span_at_clk(x_ptr, &result.limbs, clk + 1);
}
