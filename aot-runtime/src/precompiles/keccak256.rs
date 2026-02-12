use crate::emulator::AotEmulatorCore;
use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;
pub const STATE_NUM_WORDS: usize = STATE_SIZE * 2;

/// Keccak256 permute syscall implementation with span operations.
pub fn keccak_permute(core: &mut AotEmulatorCore, state_ptr: u32) {
    let clk = core.clk;

    // Stack-allocated buffer for state (50 words = 200 bytes)
    let mut state_values = [0u32; STATE_NUM_WORDS];
    core.read_mem_span_at_clk(state_ptr, &mut state_values, clk);

    // Convert to u64 state (stack-allocated)
    let mut state = [0u64; STATE_SIZE];
    for i in 0..STATE_SIZE {
        let least_sig = state_values[i * 2];
        let most_sig = state_values[i * 2 + 1];
        state[i] = least_sig as u64 + ((most_sig as u64) << 32);
    }

    keccakf(&mut state);

    // Convert back to u32 (stack-allocated)
    let mut values_to_write = [0u32; STATE_NUM_WORDS];
    for i in 0..STATE_SIZE {
        let most_sig = ((state[i] >> 32) & 0xFFFFFFFF) as u32;
        let least_sig = (state[i] & 0xFFFFFFFF) as u32;
        values_to_write[i * 2] = least_sig;
        values_to_write[i * 2 + 1] = most_sig;
    }

    // Write using span operation
    core.write_mem_span_at_clk(state_ptr, &values_to_write, clk + 1);
}
