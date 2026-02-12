use crate::emulator::AotEmulatorCore;
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use pico_vm::primitives::{consts::PERMUTATION_WIDTH, Poseidon2Init};

/// Poseidon2 permute syscall implementation with span operations.
pub fn poseidon2_permute<F>(
    core: &mut AotEmulatorCore,
    input_memory_ptr: u32,
    output_memory_ptr: u32,
) where
    F: PrimeField32 + Poseidon2Init,
    F::Poseidon2: Permutation<[F; 16]>,
{
    let clk = core.clk;

    // Stack-allocated buffer (16 words = 64 bytes)
    let mut state_values = [0u32; PERMUTATION_WIDTH];
    core.read_mem_span_at_clk(input_memory_ptr, &mut state_values, clk);

    // Convert to field elements (directly map without intermediate Vec)
    let state: [F; PERMUTATION_WIDTH] = {
        let mut arr = [F::from_canonical_u32(0); PERMUTATION_WIDTH];
        for i in 0..PERMUTATION_WIDTH {
            arr[i] = F::from_canonical_u32(state_values[i]);
        }
        arr
    };

    let state = F::init().permute(state);

    // Convert back to u32 and write using span operation
    let output = state.map(|f| f.as_canonical_u32());
    core.write_mem_span_at_clk(output_memory_ptr, &output, clk + 1);
}
