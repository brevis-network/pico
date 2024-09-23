use crate::chips::memory::initialize_finalize::{
    columns::{MemoryInitializeFinalizeCols, NUM_MEMORY_INITIALIZE_FINALIZE_COLS},
    MemoryChipType, MemoryInitializeFinalizeChip,
};
use log::{debug, info};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_emulator::riscv::{events::MemoryInitializeFinalizeEvent, record::EmulationRecord};
use pico_machine::{chip::ChipBehavior, utils::pad_to_power_of_two};
use std::{array, borrow::BorrowMut};

impl<F: Field> ChipBehavior<F> for MemoryInitializeFinalizeChip<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        match self.kind {
            MemoryChipType::Initialize => "MemoryInit".to_string(),
            MemoryChipType::Finalize => "MemoryFinalize".to_string(),
        }
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        debug!("{} chip - generate_main: BEGIN", self.name());

        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.memory_finalize_events.clone(),
        };

        let previous_addr_bits = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr_bits,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr_bits,
        };

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

                let mut row = [F::zero(); NUM_MEMORY_INITIALIZE_FINALIZE_COLS];
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
                    cols.is_last_addr = F::one();
                }

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_INITIALIZE_FINALIZE_COLS,
        );

        pad_to_power_of_two::<NUM_MEMORY_INITIALIZE_FINALIZE_COLS, F>(&mut trace.values);

        debug!(
            "{} chip - generate_main: END - trace len {}",
            self.name(),
            trace.values.len()
        );

        trace
    }
}
