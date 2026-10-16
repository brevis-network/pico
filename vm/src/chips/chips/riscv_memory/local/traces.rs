use std::borrow::BorrowMut;

use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_global::event::GlobalInteractionEvent,
            riscv_memory::event::{is_fresh_local_mem_event, MemoryLocalEvent},
        },
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{
        chip::ChipBehavior,
        estimator::EventCapture,
        lookup::{LookupScope, LookupType},
    },
    primitives::consts::LOCAL_MEMORY_DATAPAR,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

/// Split a u64 addr into 3×u16 limbs.
#[inline(always)]
fn addr_to_u16_limbs(addr: u64) -> [u32; 3] {
    [
        (addr & 0xFFFF) as u32,
        ((addr >> 16) & 0xFFFF) as u32,
        ((addr >> 32) & 0xFFFF) as u32,
    ]
}

/// Split a u64 value into 4×u16 limbs.
#[inline(always)]
fn value_to_u16_limbs(value: u64) -> [u32; 4] {
    [
        (value & 0xFFFF) as u32,
        ((value >> 16) & 0xFFFF) as u32,
        ((value >> 32) & 0xFFFF) as u32,
        ((value >> 48) & 0xFFFF) as u32,
    ]
}

/// Build a packed 8-slot Global message from (chunk, clk, addr, value).
/// Layout: [chunk, clk, addr[0], addr[1], addr[2], v0+v2_lower<<16, v1+v2_upper<<16, v3]
///
/// v2 packing trick: v[2] is split into v2_lower (bits 0..7) and v2_upper (bits 8..15),
/// then packed into slot5 and slot6 respectively.
#[inline(always)]
fn build_global_message(chunk: u32, clk: u32, addr: u64, value: u64) -> [u32; 8] {
    let a = addr_to_u16_limbs(addr);
    let v = value_to_u16_limbs(value);
    let v2_lower = v[2] & 0xFF; // lower 8 bits of v[2]
    let v2_upper = (v[2] >> 8) & 0xFF; // upper 8 bits of v[2]
    [
        chunk,
        clk,
        a[0],
        a[1],
        a[2],
        v[0] + (v2_lower << 16), // slot5: v0 + v2_lower<<16
        v[1] + (v2_upper << 16), // slot6: v1 + v2_upper<<16
        v[3],                    // slot7: v3
    ]
}

/// Split an entry into the shape flag, the `clk` its initial state puts on the regional bus, and
/// `final_clk - initial_clk - 1`.
///
/// An interval that starts in an earlier chunk cannot name its real `initial_clk` on the regional
/// bus — that clock belongs to a chunk which has since reset — so it carries the sentinel `0`,
/// which is what the first access of the interval also names as its `prev_clk`. Intervals that
/// start inside this chunk carry the real value, and only those get the `initial_clk < final_clk`
/// check (the diff is unconstrained, hence zero, on the others).
#[inline(always)]
fn normalize_initial(event: &MemoryLocalEvent) -> (bool, u32, u64) {
    let initial = &event.initial_mem_access;
    let final_ = &event.final_mem_access;
    if initial.chunk == final_.chunk {
        let diff = u64::from(final_.timestamp) - u64::from(initial.timestamp) - 1;
        assert!(
            diff < (1 << 25),
            "memory-local clk diff {diff} exceeds the 25-bit budget"
        );
        (true, initial.timestamp, diff)
    } else {
        (false, 0, 0)
    }
}

impl<F: PrimeField32> ChipBehavior<F> for MemoryLocalChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryLocal".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.get_local_mem_events().collect::<Vec<_>>();
        let image = &input.program.memory_image;
        let nb_rows = events.len().div_ceil(LOCAL_MEMORY_DATAPAR);
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = next_power_of_two(nb_rows, log_rows);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_MEMORY_LOCAL_INIT_COLS);

        // Parallelize the main computation using par_chunks_mut
        values[..nb_rows * NUM_MEMORY_LOCAL_INIT_COLS]
            .par_chunks_mut(NUM_MEMORY_LOCAL_INIT_COLS)
            .enumerate()
            .for_each(|(row_idx, row)| {
                let base_event_idx = row_idx * LOCAL_MEMORY_DATAPAR;
                let cols: &mut MemoryLocalCols<F> = row.borrow_mut();

                for k in 0..LOCAL_MEMORY_DATAPAR {
                    let cols = &mut cols.memory_local_entries[k];
                    if base_event_idx + k < events.len() {
                        let event = &events[base_event_idx + k];

                        // addr: 3×u16 limbs directly from u64
                        let addr_limbs = addr_to_u16_limbs(event.addr);
                        cols.addr = addr_limbs.map(F::from_u32);

                        cols.initial_chunk = F::from_u32(event.initial_mem_access.chunk);
                        cols.final_chunk = F::from_u32(event.final_mem_access.chunk);
                        cols.initial_clk = F::from_u32(event.initial_mem_access.timestamp);
                        cols.final_clk = F::from_u32(event.final_mem_access.timestamp);

                        // Value: 4×u16 limbs directly from u64
                        let init_v = value_to_u16_limbs(event.initial_mem_access.value);
                        cols.initial_value = crate::compiler::word::Word(init_v.map(F::from_u32));

                        let final_v = value_to_u16_limbs(event.final_mem_access.value);
                        cols.final_value = crate::compiler::word::Word(final_v.map(F::from_u32));

                        // v2 packing: value[2] = value_lower + value_upper * 256
                        cols.initial_value_lower = F::from_u32(init_v[2] & 0xFF);
                        cols.initial_value_upper = F::from_u32((init_v[2] >> 8) & 0xFF);
                        cols.final_value_lower = F::from_u32(final_v[2] & 0xFF);
                        cols.final_value_upper = F::from_u32((final_v[2] >> 8) & 0xFF);

                        // Which shape this entry has, and the normalized `clk` that follows.
                        let (in_chunk, clk_regional, clk_diff) = normalize_initial(event);
                        cols.initial_in_chunk = F::from_bool(in_chunk);
                        cols.initial_clk_regional = F::from_u32(clk_regional);
                        cols.clk_diff_16bit_limb = F::from_u16((clk_diff & 0xffff) as u16);
                        cols.clk_diff_hi9 = F::from_u16(((clk_diff >> 16) & 0x1ff) as u16);

                        cols.is_real = F::ONE;
                        // A fresh entry declares its (zero) initial state instead of receiving
                        // it; see `riscv_memory/event.rs`.
                        cols.has_initial = F::from_bool(!is_fresh_local_mem_event(event, image));
                    }
                }
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_MEMORY_LOCAL_INIT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let local_mem_events = input.get_local_mem_events().collect::<Vec<_>>();
        let image = &input.program.memory_image;
        let nb_rows = local_mem_events.len().div_ceil(4);
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        let (global_events, blu_batches): (Vec<_>, Vec<_>) = local_mem_events
            .par_chunks(chunk_size * LOCAL_MEMORY_DATAPAR)
            .map(|events| {
                let mut global_events = vec![];
                let mut blu = vec![];

                events.chunks(LOCAL_MEMORY_DATAPAR).for_each(|events| {
                    for k in 0..LOCAL_MEMORY_DATAPAR {
                        if k < events.len() {
                            let event = events[k];

                            // --- Byte lookup events ---

                            // Initial value: u8 range check for v2 packing cols
                            let init_v2_lower =
                                ((event.initial_mem_access.value >> 32) & 0xFF) as u8;
                            let init_v2_upper =
                                ((event.initial_mem_access.value >> 40) & 0xFF) as u8;
                            blu.add_u8_range_check(init_v2_lower, init_v2_upper);

                            // Initial value: u16 range check for limbs 0 and 1 only (the two
                            // Global packing slots); the AIR binds the other limbs through the
                            // memory bus (`local/constraints.rs`).
                            let init_v = value_to_u16_limbs(event.initial_mem_access.value);
                            blu.add_u16_range_checks(&[init_v[0] as u16, init_v[1] as u16]);

                            // Final value: u8 range check for v2 packing cols
                            let final_v2_lower =
                                ((event.final_mem_access.value >> 32) & 0xFF) as u8;
                            let final_v2_upper =
                                ((event.final_mem_access.value >> 40) & 0xFF) as u8;
                            blu.add_u8_range_check(final_v2_lower, final_v2_upper);

                            // No U16 events for the final value or the address: the AIR has no
                            // range checks on them (they are bus-bound, see the constraints).

                            // Whichever shape the entry has, it pays exactly one range check:
                            // the clk gap inside the chunk, or the chunk gap across chunks.
                            let (in_chunk, _, clk_diff) = normalize_initial(event);
                            if in_chunk {
                                blu.add_u16_range_check((clk_diff & 0xffff) as u16);
                                blu.add_bit_range_check(((clk_diff >> 16) & 0x1ff) as u16, 9);
                            } else {
                                let chunk_diff = event.final_mem_access.chunk
                                    - event.initial_mem_access.chunk
                                    - 1;
                                blu.add_u16_range_check(chunk_diff as u16);
                            }

                            // --- Global interaction events ---

                            // Initial: receive interaction. A fresh entry declares its initial
                            // state on the AIR (`has_initial = 0`) and receives nothing; its
                            // byte events above are unchanged (the u8 / u16 checks still run
                            // on the zero limbs). Trace generation and the Global-event layout
                            // (`riscv_memory/event.rs`) use the same predicate.
                            if !is_fresh_local_mem_event(event, image) {
                                global_events.push(GlobalInteractionEvent {
                                    message: build_global_message(
                                        event.initial_mem_access.chunk,
                                        event.initial_mem_access.timestamp,
                                        event.addr,
                                        event.initial_mem_access.value,
                                    ),
                                    is_receive: true,
                                    kind: LookupType::Memory as u8,
                                });
                            }

                            // Final: send interaction
                            global_events.push(GlobalInteractionEvent {
                                message: build_global_message(
                                    event.final_mem_access.chunk,
                                    event.final_mem_access.timestamp,
                                    event.addr,
                                    event.final_mem_access.value,
                                ),
                                is_receive: false,
                                kind: LookupType::Memory as u8,
                            });
                        }
                    }
                });

                (global_events, blu)
            })
            .unzip();

        extra
            .global_lookup_events
            .extend(global_events.into_iter().flatten());
        extra.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
    }
    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        record.get_local_mem_events().nth(0).is_some()
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Regional
    }
}

impl<F> EventCapture for MemoryLocalChip<F> {}
