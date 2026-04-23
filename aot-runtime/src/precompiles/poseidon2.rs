use crate::emulator::AotEmulatorCore;
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use pico_vm::primitives::{consts::PERMUTATION_WIDTH, Poseidon2Init};

#[inline(always)]
fn extract_word(dword: u64, word_index: usize) -> u32 {
    ((dword >> (word_index * 32)) & 0xffff_ffff) as u32
}

#[inline(always)]
fn insert_word(dword: u64, word_index: usize, value: u32) -> u64 {
    let shift = word_index * 32;
    let mask = !(0xffff_ffff_u64 << shift);
    (dword & mask) | (u64::from(value) << shift)
}

#[inline(always)]
fn covered_dword_range(addr: u64, len: usize) -> (u64, usize, usize) {
    let start = AotEmulatorCore::dword_addr(addr);
    let start_word_index = ((addr >> 2) & 1) as usize;
    let num_dwords = (start_word_index + len).div_ceil(2);
    (start, start_word_index, num_dwords)
}

fn read_word_span_via_dwords_at_clk(
    core: &mut AotEmulatorCore,
    addr: u64,
    out: &mut [u32],
    clk: u32,
) {
    let (start, start_word_index, num_dwords) = covered_dword_range(addr, out.len());
    let mut dwords = [0u64; (PERMUTATION_WIDTH / 2) + 1];
    core.read_mem_dword_span_at_clk(start, &mut dwords[..num_dwords], clk);

    if core.in_syscall() {
        core.chunk_split_state
            .add_syscall_memory_events(out.len() - num_dwords);
    }

    for (i, slot) in out.iter_mut().enumerate() {
        let logical_word_index = start_word_index + i;
        let dword = dwords[logical_word_index / 2];
        *slot = extract_word(dword, logical_word_index % 2);
    }
}

fn write_word_span_via_dwords_at_clk(
    core: &mut AotEmulatorCore,
    addr: u64,
    values: &[u32],
    clk: u32,
) {
    let (start, start_word_index, num_dwords) = covered_dword_range(addr, values.len());
    let mut dwords = [0u64; (PERMUTATION_WIDTH / 2) + 1];
    for (i, slot) in dwords[..num_dwords].iter_mut().enumerate() {
        *slot = core.read_mem_dword_unsafe(start + (i as u64) * 8);
    }

    for (i, &value) in values.iter().enumerate() {
        let logical_word_index = start_word_index + i;
        let dword_index = logical_word_index / 2;
        let word_index = logical_word_index % 2;
        dwords[dword_index] = insert_word(dwords[dword_index], word_index, value);
    }

    core.write_mem_dword_span_at_clk(start, &dwords[..num_dwords], clk);

    if core.in_syscall() {
        core.chunk_split_state
            .add_syscall_memory_events(values.len() - num_dwords);
    }
}

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
    read_word_span_via_dwords_at_clk(core, u64::from(input_memory_ptr), &mut state_values, clk);

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
    write_word_span_via_dwords_at_clk(core, u64::from(output_memory_ptr), &output, clk + 1);
}
