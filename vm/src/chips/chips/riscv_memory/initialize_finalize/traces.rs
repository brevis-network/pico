use super::{
    columns::{MemoryInitializeFinalizeCols, NUM_MEMORY_INITIALIZE_FINALIZE_COLS},
    MemoryChipType, MemoryInitializeFinalizeChip,
};
use crate::{
    chips::chips::{
        rangecheck::event::RangeLookupEvent, riscv_memory::event::MemoryInitializeFinalizeEvent,
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{
        chip::ChipBehavior, lookup::LookupScope, septic::SepticDigest, utils::pad_to_power_of_two,
    },
};
use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use std::{array, borrow::BorrowMut};

impl<F: PrimeField32> ChipBehavior<F> for MemoryInitializeFinalizeChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipType::Initialize => "MemoryInitialize".to_string(),
            MemoryChipType::Finalize => "MemoryFinalize".to_string(),
        }
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.memory_finalize_events.clone(),
        };

        let previous_addr_bits = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_initialize_addr_bits,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr_bits,
        };

        let is_receive = match self.kind {
            MemoryChipType::Initialize => false,
            MemoryChipType::Finalize => true,
        };

        let mut global_cumulative_sum = SepticDigest::<F>::zero().0;

        memory_events.sort_by_key(|event| event.addr);
        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len()) // OPT: change this to par_iter
            .map(|i| {
                let MemoryInitializeFinalizeEvent {
                    addr,
                    value,
                    chunk,
                    timestamp,
                    used,
                } = memory_events[i];

                let mut row = [F::ZERO; NUM_MEMORY_INITIALIZE_FINALIZE_COLS];
                let cols: &mut MemoryInitializeFinalizeCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.addr_bits.populate(addr);
                cols.chunk = F::from_canonical_u32(chunk);
                cols.timestamp = F::from_canonical_u32(timestamp);
                cols.value = array::from_fn(|i| F::from_canonical_u32((value >> i) & 1));
                cols.is_real = F::from_canonical_u32(used);

                if i == 0 {
                    let prev_addr = previous_addr_bits
                        .iter()
                        .enumerate()
                        .map(|(j, bit)| bit * (1 << j))
                        .sum::<u32>();
                    cols.is_prev_addr_zero.populate(prev_addr);
                    cols.is_first_comp = F::from_bool(prev_addr != 0);
                    if prev_addr != 0 {
                        debug_assert!(prev_addr < addr, "prev_addr {} < addr {}", prev_addr, addr);
                        let addr_bits: [_; 32] = array::from_fn(|i| (addr >> i) & 1);
                        cols.lt_cols.populate(&previous_addr_bits, &addr_bits);
                    }
                }

                if i != 0 {
                    let prev_is_real = memory_events[i - 1].used;
                    cols.is_next_comp = F::from_canonical_u32(prev_is_real);
                    let previous_addr = memory_events[i - 1].addr;
                    assert_ne!(previous_addr, addr);

                    let addr_bits: [_; 32] = array::from_fn(|i| (addr >> i) & 1);
                    let prev_addr_bits: [_; 32] = array::from_fn(|i| (previous_addr >> i) & 1);
                    cols.lt_cols.populate(&prev_addr_bits, &addr_bits);
                }

                if i == memory_events.len() - 1 {
                    cols.is_last_addr = F::ONE;
                }

                let interaction_chunk = if is_receive { chunk } else { 0 };
                let interaction_clk = if is_receive { timestamp } else { 0 };

                cols.global_interaction_cols.populate_memory(
                    interaction_chunk,
                    interaction_clk,
                    addr,
                    value,
                    is_receive,
                    used != 0,
                );

                cols.global_accumulation_cols.populate(
                    &mut global_cumulative_sum,
                    [cols.global_interaction_cols],
                    [cols.is_real],
                );

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INITIALIZE_FINALIZE_COLS,
        );

        // Pad the trace based on shape
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_MEMORY_INITIALIZE_FINALIZE_COLS, F>(&mut trace.values, log_rows);

        for i in memory_events.len()..trace.height() {
            let cols: &mut MemoryInitializeFinalizeCols<F> = trace.values[i
                * NUM_MEMORY_INITIALIZE_FINALIZE_COLS
                ..(i + 1) * NUM_MEMORY_INITIALIZE_FINALIZE_COLS]
                .borrow_mut();
            cols.global_interaction_cols.populate_dummy();
            cols.global_accumulation_cols.populate(
                &mut global_cumulative_sum,
                [cols.global_interaction_cols],
                [cols.is_real],
            );
        }

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.memory_finalize_events.clone(),
        };

        let is_receive = match self.kind {
            MemoryChipType::Initialize => false,
            MemoryChipType::Finalize => true,
        };

        memory_events.sort_by_key(|event| event.addr);
        let chunk_size = std::cmp::max(memory_events.len() / num_cpus::get(), 1);

        let rangecheck_events = memory_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<RangeLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let MemoryInitializeFinalizeEvent {
                        addr: _addr,
                        value,
                        chunk,
                        timestamp: _timestamp,
                        used,
                    } = event.to_owned();
                    let interaction_chunk = if is_receive { chunk } else { 0 };
                    let mut row = [F::ZERO; NUM_MEMORY_INITIALIZE_FINALIZE_COLS];
                    let cols: &mut MemoryInitializeFinalizeCols<F> =
                        row.as_mut_slice().borrow_mut();
                    cols.global_interaction_cols
                        .populate_memory_range_check_witness(
                            interaction_chunk,
                            value,
                            used != 0,
                            &mut blu,
                        );
                });
                blu
            })
            .collect::<Vec<_>>();
        extra.add_rangecheck_lookup_events(rangecheck_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self.kind {
            MemoryChipType::Initialize => !record.memory_initialize_events.is_empty(),
            MemoryChipType::Finalize => !record.memory_finalize_events.is_empty(),
        }
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Global
    }
}
