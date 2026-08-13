//! Unused by `default_syscall_map`: this syscall is not registered while its chip is out of the
//! machine, so nothing here is reachable from a non-test build. Kept whole so the implementation
//! is ready if it returns, and constructed directly by the poseidon2 tests in `chips/tests.rs` so
//! it stays exercised meanwhile. See `syscalls/mod.rs`.
#![allow(dead_code)]

use super::event::Poseidon2PermuteEvent;
use crate::{
    chips::chips::riscv_memory::event::{MemoryReadRecord, MemoryWriteRecord},
    emulator::riscv::{
        emulator::util::align_u64,
        event_types::RvValue,
        syscalls::{
            precompiles::PrecompileEvent, syscall_context::SyscallContext, Syscall, SyscallCode,
        },
    },
    primitives::{consts::PERMUTATION_WIDTH, Poseidon2Init},
};
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use std::marker::PhantomData;

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
    let start = align_u64(addr);
    let start_word_index = ((addr >> 2) & 1) as usize;
    let num_dwords = (start_word_index + len).div_ceil(2);
    (start, start_word_index, num_dwords)
}

fn read_word_records_via_dwords(
    ctx: &mut SyscallContext,
    addr: u64,
    len: usize,
) -> (Vec<MemoryReadRecord>, Vec<u32>) {
    let (start, start_word_index, num_dwords) = covered_dword_range(addr, len);
    let (dword_records, dwords) = ctx.mr_dword_slice(start, num_dwords);

    if len > num_dwords {
        ctx.rt
            .chunk_split_state
            .add_syscall_memory_events(len - num_dwords);
    }

    let mut records = Vec::with_capacity(len);
    let mut values = Vec::with_capacity(len);
    for i in 0..len {
        let logical_word_index = start_word_index + i;
        let dword_index = logical_word_index / 2;
        let word_index = logical_word_index % 2;
        let record = dword_records[dword_index];
        records.push(record);
        values.push(extract_word(dwords[dword_index], word_index));
    }

    (records, values)
}

fn write_word_records_via_dwords(
    ctx: &mut SyscallContext,
    addr: u64,
    values: &[u32],
) -> Vec<MemoryWriteRecord> {
    let (start, start_word_index, num_dwords) = covered_dword_range(addr, values.len());
    let mut final_dwords = ctx.dword_slice_unsafe(start, num_dwords);
    let mut per_dword_sequences = vec![Vec::new(); num_dwords];

    for (i, &value) in values.iter().enumerate() {
        let logical_word_index = start_word_index + i;
        let dword_index = logical_word_index / 2;
        let word_index = logical_word_index % 2;
        let prev_value = final_dwords[dword_index];
        let next_value = insert_word(prev_value, word_index, value);
        per_dword_sequences[dword_index].push((prev_value, next_value));
        final_dwords[dword_index] = next_value;
    }

    let dword_write_records = ctx.mw_dword_slice(start, &final_dwords);

    if values.len() > num_dwords {
        ctx.rt
            .chunk_split_state
            .add_syscall_memory_events(values.len() - num_dwords);
    }

    let mut sequence_offsets = vec![0usize; num_dwords];
    let mut records = Vec::with_capacity(values.len());
    for i in 0..values.len() {
        let logical_word_index = start_word_index + i;
        let dword_index = logical_word_index / 2;
        let dword_record = dword_write_records[dword_index];
        let (prev_value, next_value) =
            per_dword_sequences[dword_index][sequence_offsets[dword_index]];
        sequence_offsets[dword_index] += 1;
        records.push(MemoryWriteRecord {
            value: next_value,
            chunk: dword_record.chunk,
            timestamp: dword_record.timestamp,
            prev_value,
            prev_chunk: dword_record.prev_chunk,
            prev_timestamp: dword_record.prev_timestamp,
        });
    }

    records
}

#[allow(clippy::type_complexity)]
pub(crate) struct Poseidon2PermuteSyscall<F>(pub(crate) PhantomData<fn(F) -> F>);

impl<F> Syscall for Poseidon2PermuteSyscall<F>
where
    F: PrimeField32 + Poseidon2Init,
    F::Poseidon2: Permutation<[F; 16]>,
{
    fn num_extra_cycles(&self) -> u32 {
        1
    }

    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let clk_init = ctx.clk;
        let input_memory_ptr = arg1;
        let output_memory_ptr = arg2;

        // Both pointers must be 8-byte aligned, same as every other precompile.
        //
        // The AIR requires it: `SyscallAddrGadget::eval` range checks `addr[0] * 8^-1` to 13 bits,
        // which only holds when `addr[0]` is a multiple of 8 (a non-multiple maps to a field
        // element on the order of p/8). Without this assertion the two sides disagreed -- the
        // helpers below align down and track a 4-byte offset, so an unaligned pointer emulated
        // fine and then had no provable trace. Failing here says why; failing in the prover
        // showed up only as an unbalanced bus.
        SyscallContext::assert_dword_aligned_precompile(input_memory_ptr, "poseidon2 input_ptr");
        SyscallContext::assert_dword_aligned_precompile(output_memory_ptr, "poseidon2 output_ptr");

        let (state_records, state_values) =
            read_word_records_via_dwords(ctx, input_memory_ptr, PERMUTATION_WIDTH);
        let state_read_records = state_records;

        let state: [F; PERMUTATION_WIDTH] = state_values
            .iter()
            .copied()
            .map(F::from_canonical_u32)
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        let state = F::init().permute(state);

        // Increment the clk by 1 before writing because we read from memory at start_clk.
        ctx.clk += 1;

        let write_vals: Vec<u32> = state.iter().map(|f| f.as_canonical_u32()).collect();
        let state_write_records =
            write_word_records_via_dwords(ctx, output_memory_ptr, &write_vals);

        let chunk = ctx.current_chunk();
        let event = Poseidon2PermuteEvent {
            chunk,
            clk: clk_init,
            state_values,
            input_memory_ptr,
            output_memory_ptr,
            state_read_records,
            state_write_records,
            local_mem_access: ctx.postprocess(),
        };

        let syscall_event = ctx
            .rt
            .syscall_event(clk_init, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Poseidon2Permute(event),
        );

        None
    }
}
