use super::PrecompileMemory;
use pico_vm::chips::precompiles::blake2b::{
    rounds, MAX_ROUNDS_PER_CALL, MESSAGE_DWORDS, STATE_DWORDS,
};

/// `BLAKE2B_ROUNDS`: rounds `0..n` of BLAKE2b's schedule on the working vector at `ptr`, with the
/// message block after it, as the VM's syscall computes it and with its refusals. `v` is read as
/// the first operand and written back at `clk`, `m` read at `clk`.
pub fn blake2b_rounds(core: &mut impl PrecompileMemory, ptr: u64, n: u64) {
    assert!(ptr.is_multiple_of(8), "BLAKE2b rounds buffer is unaligned");
    assert!(
        (1..=u64::from(MAX_ROUNDS_PER_CALL)).contains(&n),
        "BLAKE2b rounds: a call runs 1 to {MAX_ROUNDS_PER_CALL} rounds, got {n}"
    );
    let clk = core.clk();
    let mut v = [0u64; STATE_DWORDS];
    let mut m = [0u64; MESSAGE_DWORDS];
    core.read_mem_dword_span_snapshot_syscall(ptr, &mut v);
    core.read_mem_dword_span_at_clk(ptr + 8 * STATE_DWORDS as u64, &mut m, clk);
    rounds(&mut v, &m, n as u32);
    core.write_mem_dword_span_at_clk(ptr, &v, clk);
}
