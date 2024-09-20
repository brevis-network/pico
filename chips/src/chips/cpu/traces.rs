use crate::chips::{
    cpu::{
        columns::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS},
        CpuChip,
    },
    memory::read_write::columns::MemoryCols,
};
use hashbrown::HashMap;
use log::info;
use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_compiler::{opcode::Opcode, program::Program};
use pico_emulator::riscv::{
    events::{AluEvent, ByteRecord, CpuEvent, MemoryRecordEnum},
    record::EmulationRecord,
};
use pico_machine::chip::ChipBehavior;
use rayon::prelude::{IntoParallelRefMutIterator, ParallelBridge, ParallelIterator};
use std::borrow::BorrowMut;

impl<F: Field> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F: Field> ChipBehavior<F> for CpuChip<F> {
    type Record = EmulationRecord;

    /// This name is now hard-coded and is related to MachineBehavior
    fn name(&self) -> String {
        "Cpu".to_string()
    }

    fn generate_main(&self, input: &Self::Record) -> RowMajorMatrix<F> {
        info!("CpuChip - generate_main: BEGIN");
        let mut values = vec![F::zero(); input.cpu_events.len() * NUM_CPU_COLS];

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

        info!("CpuChip - generate_main: END");

        trace
    }

    /* TODO: Enable after lookup integration.
            #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
            fn generate_dependencies(&self, input: &Self::Record, output: &mut Self::Record) {
                // Generate the trace rows for each event.
                let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);

                let (alu_events, blu_events): (Vec<_>, Vec<_>) = input
                    .cpu_events
                    .par_chunks(chunk_size)
                    .map(|ops: &[CpuEvent]| {
                        let mut alu = HashMap::new();
                        // The blu map stores shard -> map(byte lookup event -> multiplicity).
                        let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                        ops.iter().for_each(|op| {
                            let mut row = [F::zero(); NUM_CPU_COLS];
                            let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                            let alu_events = self.event_to_row::<F>(op, &HashMap::new(), cols, &mut blu);
                            alu_events.into_iter().for_each(|(key, value)| {
                                alu.entry(key).or_insert(Vec::default()).extend(value);
                            });
                        });
                        (alu, blu)
                    })
                    .unzip();

                for alu_events_chunk in alu_events.into_iter() {
                    output.add_alu_events(alu_events_chunk);
                }

                output.add_sharded_byte_lookup_events(blu_events.iter().collect_vec());
            }

        fn included(&self, input: &Self::Record) -> bool {
            !input.cpu_events.is_empty()
        }
    */
}

impl<F: Field> CpuChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<u128, u32>,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecord,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let mut new_alu_events = HashMap::new();

        // Populate shard and clk columns.
        self.populate_shard_clk(cols, event, blu_events);

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
            cols.op_a_access.populate(event.channel, record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(event.channel, record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(event.channel, record, blu_events);
        }

        /* TODO: Enable after adding the byte chip.
                // Populate range checks for a.
                let a_bytes = cols
                    .op_a_access
                    .access
                    .value
                    .0
                    .iter()
                    .map(|x| x.as_canonical_u32())
                    .collect::<Vec<_>>();
                blu_events.add_byte_lookup_event(ByteLookupEvent {
                    shard: event.shard,
                    channel: event.channel,
                    opcode: ByteOpcode::U8Range,
                    a1: 0,
                    a2: 0,
                    b: a_bytes[0] as u8,
                    c: a_bytes[1] as u8,
                });
                blu_events.add_byte_lookup_event(ByteLookupEvent {
                    shard: event.shard,
                    channel: event.channel,
                    opcode: ByteOpcode::U8Range,
                    a1: 0,
                    a2: 0,
                    b: a_bytes[2] as u8,
                    c: a_bytes[3] as u8,
                });
        */

        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        let memory_columns = cols.opcode_specific.memory_mut();
        if let Some(record) = event.memory_record {
            memory_columns
                .memory_access
                .populate(event.channel, record, blu_events)
        }

        // Populate memory, branch, jump, and auipc specific fields.
        self.populate_memory(cols, event, &mut new_alu_events, blu_events, nonce_lookup);
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
        cols.is_real = F::one();

        new_alu_events
    }

    fn pad_to_power_of_two(values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::zero());

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..].par_iter_mut().for_each(|padded_row| {
            padded_row[CPU_COL_MAP.opcode_selector.imm_b] = F::one();
            padded_row[CPU_COL_MAP.opcode_selector.imm_c] = F::one();
        });
    }
}
