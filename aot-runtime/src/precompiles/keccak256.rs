use crate::emulator::AotEmulatorCore;
use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;

/// Keccak256 permute syscall implementation with span operations.
pub fn keccak_permute(core: &mut AotEmulatorCore, state_ptr: u64) {
    let clk = core.clk;

    // Match the interpreter's dword-granular keccak syscall accounting.
    let mut state = [0u64; STATE_SIZE];
    core.read_mem_dword_span_at_clk(state_ptr, &mut state, clk);

    keccakf(&mut state);

    core.write_mem_dword_span_at_clk(state_ptr, &state, clk + 1);
}
