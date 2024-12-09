use super::{
    columns::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS},
    CpuChip,
};
use crate::{
    chips::chips::{
        alu::event::AluEvent,
        rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
        riscv_cpu::event::CpuEvent,
        riscv_memory::{event::MemoryRecordEnum, read_write::columns::MemoryCols},
    },
    compiler::riscv::{
        opcode::{Opcode, RangeCheckOpcode::U8},
        program::Program,
    },
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
};
use hashbrown::HashMap;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelSlice;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelBridge, ParallelIterator};
use std::borrow::BorrowMut;
use tracing::debug;

impl<F: Field> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F: PrimeField32> ChipBehavior<F> for CpuChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    /// This name is now hard-coded and is related to MachineBehavior
    fn name(&self) -> String {
        "Cpu".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut values = vec![F::ZERO; input.cpu_events.len() * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_CPU_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuCols<F> = row.borrow_mut();
                        let mut byte_lookup_events = Vec::new();
                        self.event_to_row(
                            &input.cpu_events[idx],
                            &input.nonce_lookup,
                            cols,
                            &mut byte_lookup_events,
                        );
                    });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two(&mut trace.values);

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let (alu_events, range_events): (Vec<_>, Vec<_>) = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                let mut alu = HashMap::new();
                // The range map stores range (u8) lookup event -> multiplicity.
                let mut range_events: HashMap<RangeLookupEvent, usize> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let alu_events =
                        self.event_to_row(op, &HashMap::new(), cols, &mut range_events);
                    alu_events.into_iter().for_each(|(key, value)| {
                        alu.entry(key).or_insert(Vec::default()).extend(value);
                    });
                });
                (alu, range_events)
            })
            .unzip();
        for alu_events_chunk in alu_events.into_iter() {
            extra.add_alu_events(alu_events_chunk);
        }
        extra.add_rangecheck_lookup_events(range_events);

        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.cpu_events.is_empty()
    }
}

impl<F: PrimeField32> CpuChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<u128, u32>,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl RangeRecordBehavior,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let chunk = event.chunk;

        let mut new_alu_events = HashMap::new();

        // Populate chunk and clk columns.
        self.populate_chunk_clk(cols, event, blu_events);

        // Populate the nonce.
        cols.nonce = F::from_canonical_u32(
            nonce_lookup
                .get(&event.alu_lookup_id)
                .copied()
                .unwrap_or_default(),
        );

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.instruction.populate(event.instruction);
        cols.opcode_selector.populate(event.instruction);

        *cols.op_a_access.value_mut() = event.a.into();
        *cols.op_b_access.value_mut() = event.b.into();
        *cols.op_c_access.value_mut() = event.c.into();

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }

        // Populate range checks for a.
        let a_bytes = cols
            .op_a_access
            .access
            .value
            .0
            .iter()
            .map(|x| x.as_canonical_u32())
            .collect::<Vec<_>>();
        blu_events.add_range_lookup_event(RangeLookupEvent::new(
            U8,
            a_bytes[0] as u16,
            Some(chunk),
        ));
        blu_events.add_range_lookup_event(RangeLookupEvent::new(
            U8,
            a_bytes[1] as u16,
            Some(chunk),
        ));
        blu_events.add_range_lookup_event(RangeLookupEvent::new(
            U8,
            a_bytes[2] as u16,
            Some(chunk),
        ));
        blu_events.add_range_lookup_event(RangeLookupEvent::new(
            U8,
            a_bytes[3] as u16,
            Some(chunk),
        ));

        self.populate_branch(cols, event, &mut new_alu_events, nonce_lookup);
        self.populate_jump(cols, event, &mut new_alu_events, nonce_lookup);
        self.populate_auipc(cols, event, &mut new_alu_events, nonce_lookup);
        let is_halt = self.populate_ecall(cols, event, nonce_lookup);

        cols.is_sequential_instr = F::from_bool(
            !event.instruction.is_branch_instruction()
                && !event.instruction.is_jump_instruction()
                && !is_halt,
        );

        // Assert that the instruction is not a no-op.
        cols.is_real = F::ONE;

        new_alu_events
    }

    fn pad_to_power_of_two(values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::ZERO);

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..].par_iter_mut().for_each(|padded_row| {
            padded_row[CPU_COL_MAP.opcode_selector.imm_b] = F::ONE;
            padded_row[CPU_COL_MAP.opcode_selector.imm_c] = F::ONE;
        });
    }
}
