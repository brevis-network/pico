use super::{
    columns::{MemoryInitializeFinalizeCols, NUM_MEMORY_INITIALIZE_FINALIZE_COLS},
    MemoryChipType, MemoryInitializeFinalizeChip,
};
use crate::{
    chips::chips::{
        byte::event::{ByteLookupEvent, ByteRecordBehavior},
        riscv_global::event::GlobalInteractionEvent,
        riscv_memory::event::MemoryInitializeFinalizeEvent,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::record::EmulationRecord,
    iter::{IntoPicoIterator, PicoIterator},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
        lookup::{LookupScope, LookupType},
        utils::pad_to_power_of_two,
    },
    primitives::consts::u64_to_u16_limbs,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

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

        let previous_addr_limbs = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr_limbs,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr_limbs,
        };

        // Reconstruct prev_addr from PV u16 limbs for the first row.
        let pv_prev_addr: u64 = (previous_addr_limbs[0] as u64)
            | ((previous_addr_limbs[1] as u64) << 16)
            | ((previous_addr_limbs[2] as u64) << 32);

        memory_events.sort_by_key(|event| event.addr);

        let rows: Vec<[F; NUM_MEMORY_INITIALIZE_FINALIZE_COLS]> = (0..memory_events.len())
            .into_pico_iter()
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

                // Address: 3×u16 limbs
                cols.addr[0] = F::from_canonical_u16((addr & 0xFFFF) as u16);
                cols.addr[1] = F::from_canonical_u16(((addr >> 16) & 0xFFFF) as u16);
                cols.addr[2] = F::from_canonical_u16(((addr >> 32) & 0xFFFF) as u16);

                // Chunk and timestamp
                cols.chunk = F::from_canonical_u32(chunk);
                cols.timestamp = F::from_canonical_u32(timestamp);

                // Value: Word<F> (4×u16 limbs)
                cols.value = Word::from(value);

                // v2 packing columns
                cols.value_lower = F::from_canonical_u32((value >> 32 & 0xFF) as u32);
                cols.value_upper = F::from_canonical_u32((value >> 40 & 0xFF) as u32);

                cols.is_real = F::from_canonical_u32(used);

                // Previous address
                let prev_addr = if i == 0 {
                    pv_prev_addr
                } else {
                    memory_events[i - 1].addr
                };

                cols.prev_addr[0] = F::from_canonical_u16((prev_addr & 0xFFFF) as u16);
                cols.prev_addr[1] = F::from_canonical_u16(((prev_addr >> 16) & 0xFFFF) as u16);
                cols.prev_addr[2] = F::from_canonical_u16(((prev_addr >> 32) & 0xFFFF) as u16);

                // is_prev_addr_zero (first row only uses PV prev_addr)
                if i == 0 {
                    // Must match constraint: prev_addr_sum = prev_addr[0] + [1] + [2]
                    let prev_addr_limb_sum: u32 = (prev_addr & 0xFFFF) as u32
                        + ((prev_addr >> 16) & 0xFFFF) as u32
                        + ((prev_addr >> 32) & 0xFFFF) as u32;
                    // sum of 3 u16 limbs; max = 196605 < u32::MAX
                    cols.is_prev_addr_zero.populate(prev_addr_limb_sum);
                    cols.is_comp = if prev_addr != 0 { F::ONE } else { F::ZERO };
                } else {
                    // On non-first rows, is_comp = is_real (always compare if real).
                    cols.is_comp = F::from_canonical_u32(used);
                }

                // LtWordU16Gadget: populate when comparison is active.
                if cols.is_comp == F::ONE {
                    debug_assert!(
                        prev_addr < addr,
                        "prev_addr 0x{prev_addr:x} must be < addr 0x{addr:x}"
                    );
                    let mut blu_scratch = Vec::new();
                    cols.lt_cols.populate(&mut blu_scratch, 1, prev_addr, addr);
                    // BLU events from lt_cols are handled in extra_record.
                }

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

        let previous_addr_limbs = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr_limbs,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr_limbs,
        };
        let pv_prev_addr: u64 = (previous_addr_limbs[0] as u64)
            | ((previous_addr_limbs[1] as u64) << 16)
            | ((previous_addr_limbs[2] as u64) << 32);

        memory_events.sort_by_key(|event| event.addr);

        // Collect BLU events and Global interaction events
        let mut blu_events: Vec<ByteLookupEvent> = Vec::new();
        let mut global_events: Vec<GlobalInteractionEvent> =
            Vec::with_capacity(memory_events.len());

        for (i, event) in memory_events.iter().enumerate() {
            let addr = event.addr;
            let value = event.value;

            // Range check: value as 4×u16 limbs
            let value_limbs = u64_to_u16_limbs(value);
            blu_events.add_u16_range_checks(&value_limbs);

            // Range check: addr as 3×u16 limbs
            let addr_limbs = u64_to_u16_limbs(addr);
            blu_events.add_u16_range_checks(&addr_limbs[0..3]);

            // Range check: prev_addr as 3×u16 limbs
            let prev_addr = if i == 0 {
                pv_prev_addr
            } else {
                memory_events[i - 1].addr
            };
            let prev_addr_limbs = u64_to_u16_limbs(prev_addr);
            blu_events.add_u16_range_checks(&prev_addr_limbs[0..3]);

            // v2 packing: u8 range checks for value_lower/value_upper
            let value_lower = (value >> 32 & 0xFF) as u8;
            let value_upper = (value >> 40 & 0xFF) as u8;
            blu_events.add_u8_range_check(value_lower, value_upper);

            // LtWordU16Gadget BLU events
            if prev_addr != 0 || i != 0 {
                // The gadget emits a u16 range check event for the diff.
                let mut lt_blu = Vec::new();
                let mut gadget =
                    crate::chips::gadgets::lt_word_u16::LtWordU16Gadget::<F>::default();
                gadget.populate(&mut lt_blu, 1, prev_addr, addr);
                blu_events.extend(lt_blu);
            }

            // Global interaction event
            let interaction_chunk = if is_receive { event.chunk } else { 0 };
            let interaction_clk = if is_receive { event.timestamp } else { 0 };
            let a0 = (addr & 0xFFFF) as u32;
            let a1 = ((addr >> 16) & 0xFFFF) as u32;
            let a2 = ((addr >> 32) & 0xFFFF) as u32;
            // v2 packing: slot5 = v0 + v2_lower<<16, slot6 = v1 + v2_upper<<16
            let slot5 = (value & 0xFFFF) as u32 + ((value >> 32 & 0xFF) as u32) * (1 << 16);
            let slot6 = ((value >> 16) & 0xFFFF) as u32 + ((value >> 40 & 0xFF) as u32) * (1 << 16);
            let slot7 = ((value >> 48) & 0xFFFF) as u32;

            global_events.push(GlobalInteractionEvent {
                message: [
                    interaction_chunk,
                    interaction_clk,
                    a0,
                    a1,
                    a2,
                    slot5,
                    slot6,
                    slot7,
                ],
                is_receive,
                kind: LookupType::Memory as u8,
            });
        }

        extra.add_byte_lookup_events(blu_events);
        extra.global_lookup_events.extend(global_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self.kind {
            MemoryChipType::Initialize => !record.memory_initialize_events.is_empty(),
            MemoryChipType::Finalize => !record.memory_finalize_events.is_empty(),
        }
    }

    fn lookup_scope(&self) -> LookupScope {
        LookupScope::Regional
    }
}

impl<F> EventCapture for MemoryInitializeFinalizeChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_memory_initialize_events += record.memory_initialize_events.len();
        event_counter.num_memory_finalize_events += record.memory_finalize_events.len();
        event_counter.num_global_lookup_events += record.memory_initialize_events.len();
        event_counter.num_global_lookup_events += record.memory_finalize_events.len();
    }
}
