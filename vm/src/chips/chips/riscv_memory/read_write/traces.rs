use super::{
    columns::{
        MemoryAccessCols, MemoryChipCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols,
        NUM_MEMORY_CHIP_COLS,
    },
    MemoryReadWriteChip,
};
use crate::{
    chips::{
        chips::{
            alu::event::AluEvent,
            rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
            riscv_cpu::event::CpuEvent,
            riscv_memory::event::{
                MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord,
            },
        },
        utils::create_alu_lookups,
    },
    compiler::riscv::{
        opcode::{Opcode, RangeCheckOpcode},
        program::Program,
        register::Register::X0,
    },
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
    primitives::consts::WORD_SIZE,
};
use hashbrown::HashMap;
use itertools::Itertools;
use log::debug;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use std::{array, borrow::BorrowMut};

impl<F: Field> ChipBehavior<F> for MemoryReadWriteChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryReadWrite".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // We only care about the CPU events of memory instructions.
        let mem_events = input
            .cpu_events
            .iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect_vec();
        let mut values = vec![F::zero(); mem_events.len() * NUM_MEMORY_CHIP_COLS];

        let chunk_size = std::cmp::max(mem_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_MEMORY_CHIP_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_MEMORY_CHIP_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut MemoryChipCols<F> = row.borrow_mut();
                        let mut byte_lookup_events = Vec::new();
                        self.event_to_row(
                            mem_events[idx],
                            &input.nonce_lookup,
                            cols,
                            &mut byte_lookup_events,
                        );
                    });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_MEMORY_CHIP_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_CHIP_COLS, F>(&mut trace.values);

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        // We only care about the CPU events of memory instructions.
        let mem_events = input
            .cpu_events
            .iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect_vec();
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(mem_events.len() / num_cpus::get(), 1);
        let (alu_events, range_events): (Vec<_>, Vec<_>) = mem_events
            .par_chunks(chunk_size)
            .map(|ops: &[&CpuEvent]| {
                let mut alu = HashMap::new();
                // The range map stores range (u8) lookup event -> multiplicity.
                let mut range_events: HashMap<RangeLookupEvent, usize> = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::zero(); NUM_MEMORY_CHIP_COLS];
                    let cols: &mut MemoryChipCols<F> = row.as_mut_slice().borrow_mut();
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
        record
            .cpu_events
            .iter()
            .any(|e| e.instruction.is_memory_instruction())
    }
}

impl<F: Field> MemoryReadWriteChip<F> {
    fn event_to_row(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<u128, u32>,
        cols: &mut MemoryChipCols<F>,
        range_events: &mut impl RangeRecordBehavior,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let mut alu_events = HashMap::new();

        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.clk = F::from_canonical_u32(event.clk);

        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        if let Some(record) = event.memory_record {
            cols.memory_access
                .populate(event.channel, record, range_events);
        }

        cols.instruction.populate(event);
        self.populate_memory(cols, event, &mut alu_events, range_events, nonce_lookup);

        alu_events
    }

    fn populate_memory(
        &self,
        cols: &mut MemoryChipCols<F>,
        event: &CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
        range_events: &mut impl RangeRecordBehavior,
        nonce_lookup: &HashMap<u128, u32>,
    ) {
        assert!(
            matches!(
                event.instruction.opcode,
                Opcode::LB
                    | Opcode::LH
                    | Opcode::LW
                    | Opcode::LBU
                    | Opcode::LHU
                    | Opcode::SB
                    | Opcode::SH
                    | Opcode::SW
            ),
            "Must be a memory opcode"
        );

        // Populate addr_word and addr_aligned columns.
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        cols.addr_word = memory_addr.into();
        cols.addr_word_range_checker.populate(memory_addr);
        cols.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        cols.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));

        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            lookup_id: event.memory_add_lookup_id,
            chunk: event.chunk,
            channel: event.channel,
            clk: event.clk,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.b,
            c: event.c,
            sub_lookups: create_alu_lookups(),
        };
        new_alu_events
            .entry(Opcode::ADD)
            .and_modify(|op_new_events| op_new_events.push(add_event))
            .or_insert(vec![add_event]);

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        cols.addr_offset = F::from_canonical_u8(addr_offset);
        cols.offset_is_one = F::from_bool(addr_offset == 1);
        cols.offset_is_two = F::from_bool(addr_offset == 2);
        cols.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            event.instruction.opcode,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        ) {
            match event.instruction.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte: u8;
                let sign_value: u32;
                if matches!(event.instruction.opcode, Opcode::LB) {
                    sign_value = 256;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[0];
                } else {
                    // LHU case
                    sign_value = 65536;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[1];
                };

                for i in (0..8).rev() {
                    cols.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if cols.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg_not_x0 =
                        F::from_bool(event.instruction.op_a != (X0 as u32));
                    let sub_event = AluEvent {
                        lookup_id: event.memory_sub_lookup_id,
                        channel: event.channel,
                        chunk: event.chunk,
                        clk: event.clk,
                        opcode: Opcode::SUB,
                        a: event.a,
                        b: cols.unsigned_mem_val.to_u32(),
                        c: sign_value,
                        sub_lookups: create_alu_lookups(),
                    };
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.memory_sub_lookup_id)
                            .copied()
                            .unwrap_or_default(),
                    );

                    new_alu_events
                        .entry(Opcode::SUB)
                        .and_modify(|op_new_events| op_new_events.push(sub_event))
                        .or_insert(vec![sub_event]);
                }
            }

            // Set the `mem_value_is_pos_not_x0` composite flag.
            cols.mem_value_is_pos_not_x0 = F::from_bool(
                ((matches!(event.instruction.opcode, Opcode::LB | Opcode::LH)
                    && (cols.most_sig_byte_decomp[7] == F::zero()))
                    || matches!(
                        event.instruction.opcode,
                        Opcode::LBU | Opcode::LHU | Opcode::LW
                    ))
                    && event.instruction.op_a != (X0 as u32),
            );
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            range_events.add_range_lookup_event(RangeLookupEvent::new(
                RangeCheckOpcode::U8,
                byte_pair[0] as u16,
            ));
            range_events.add_range_lookup_event(RangeLookupEvent::new(
                RangeCheckOpcode::U8,
                byte_pair[1] as u16,
            ));
        }
    }
}

impl<F: Field> MemoryWriteCols<F> {
    pub fn populate(
        &mut self,
        channel: u8,
        record: MemoryWriteRecord,
        output: &mut impl RangeRecordBehavior,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            chunk: record.chunk,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.prev_value,
            chunk: record.prev_chunk,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(channel, current_record, prev_record, output);
    }
}

impl<F: Field> MemoryReadCols<F> {
    pub fn populate(
        &mut self,
        channel: u8,
        record: MemoryReadRecord,
        output: &mut impl RangeRecordBehavior,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            chunk: record.chunk,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.value,
            chunk: record.prev_chunk,
            timestamp: record.prev_timestamp,
        };
        self.access
            .populate_access(channel, current_record, prev_record, output);
    }
}

impl<F: Field> MemoryReadWriteCols<F> {
    pub fn populate(
        &mut self,
        channel: u8,
        record: MemoryRecordEnum,
        output: &mut impl RangeRecordBehavior,
    ) {
        match record {
            MemoryRecordEnum::Read(read_record) => self.populate_read(channel, read_record, output),
            MemoryRecordEnum::Write(write_record) => {
                self.populate_write(channel, write_record, output)
            }
        }
    }

    pub fn populate_write(
        &mut self,
        channel: u8,
        record: MemoryWriteRecord,
        output: &mut impl RangeRecordBehavior,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            chunk: record.chunk,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.prev_value,
            chunk: record.prev_chunk,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(channel, current_record, prev_record, output);
    }

    pub fn populate_read(
        &mut self,
        channel: u8,
        record: MemoryReadRecord,
        output: &mut impl RangeRecordBehavior,
    ) {
        let current_record = MemoryRecord {
            value: record.value,
            chunk: record.chunk,
            timestamp: record.timestamp,
        };
        let prev_record = MemoryRecord {
            value: record.value,
            chunk: record.prev_chunk,
            timestamp: record.prev_timestamp,
        };
        self.prev_value = prev_record.value.into();
        self.access
            .populate_access(channel, current_record, prev_record, output);
    }
}

impl<F: Field> MemoryAccessCols<F> {
    pub(crate) fn populate_access(
        &mut self,
        channel: u8,
        current_record: MemoryRecord,
        prev_record: MemoryRecord,
        output: &mut impl RangeRecordBehavior,
    ) {
        self.value = current_record.value.into();

        self.prev_chunk = F::from_canonical_u32(prev_record.chunk);
        self.prev_clk = F::from_canonical_u32(prev_record.timestamp);

        // Fill columns used for verifying current memory access time value is greater than
        // previous's.
        let use_clk_comparison = prev_record.chunk == current_record.chunk;
        self.compare_clk = F::from_bool(use_clk_comparison);
        let prev_time_value = if use_clk_comparison {
            prev_record.timestamp
        } else {
            prev_record.chunk
        };
        let current_time_value = if use_clk_comparison {
            current_record.timestamp
        } else {
            current_record.chunk
        };

        let diff_minus_one = current_time_value - prev_time_value - 1;
        let diff_16bit_limb = (diff_minus_one & 0xffff) as u16;
        self.diff_16bit_limb = F::from_canonical_u16(diff_16bit_limb);
        let diff_8bit_limb = (diff_minus_one >> 16) & 0xff;
        self.diff_8bit_limb = F::from_canonical_u32(diff_8bit_limb);

        let chunk = current_record.chunk;

        // Add a range table lookup with the U16 op.
        output.add_u16_range_check(chunk, channel, diff_16bit_limb);
        // Add a range table lookup with the U8 op.
        output.add_u8_range_check(diff_8bit_limb as u8);
    }
}
