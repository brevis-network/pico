use super::{
    columns::{
        MemoryAccessCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols,
        NUM_MEMORY_CHIP_COLS,
    },
    MemoryReadWriteChip,
};
use crate::{
    chips::{
        chips::{
            alu::event::AluEvent,
            byte::event::ByteRecordBehavior,
            events::ByteLookupEvent,
            riscv_cpu::event::CpuEvent,
            riscv_memory::{
                event::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord},
                read_write::columns::{MemoryChipValueCols, NUM_MEMORY_CHIP_VALUE_COLS},
            },
        },
        utils::next_power_of_two,
    },
    compiler::riscv::{
        opcode::{ByteOpcode, Opcode},
        program::Program,
        register::Register::X0,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{MEMORY_RW_DATAPAR, WORD_SIZE},
};
use hashbrown::HashMap;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::{array, borrow::BorrowMut};

impl<F: PrimeField32> ChipBehavior<F> for MemoryReadWriteChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryReadWrite".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Parallelize the initial filtering and collection
        let events: Vec<_> = input
            .cpu_events
            .pico_iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect();

        let nrows = events.len().div_ceil(MEMORY_RW_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        // Pre-allocate with parallel initialization
        let mut values = vec![F::ZERO; padded_nrows * NUM_MEMORY_CHIP_COLS];

        // Calculate actual population length and handle type conversion
        let populate_len = events.len() * NUM_MEMORY_CHIP_VALUE_COLS;

        // Use rayon's parallel slice operations for better chunk handling
        values[..populate_len]
            .pico_chunks_mut(NUM_MEMORY_CHIP_VALUE_COLS)
            .zip_eq(events.pico_iter())
            .for_each(|(row, event)| {
                let cols: &mut MemoryChipValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_MEMORY_CHIP_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        // We only care about the CPU events of memory instructions.
        let mem_events = input
            .cpu_events
            .iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect::<Box<[_]>>();
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(mem_events.len() / num_cpus::get(), 1);
        let (alu_events, blu_events): (Vec<_>, Vec<_>) = mem_events
            .pico_chunks(chunk_size)
            .map(|ops: &[&CpuEvent]| {
                let mut alu = HashMap::new();
                // The range map stores range (u8) lookup event -> multiplicity.
                let mut blu = vec![];
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_MEMORY_CHIP_VALUE_COLS];
                    let cols: &mut MemoryChipValueCols<F> = row.as_mut_slice().borrow_mut();
                    let alu_events = self.event_to_row(op, cols, &mut blu);
                    alu_events.into_iter().for_each(|(key, value)| {
                        alu.entry(key).or_insert(Vec::default()).extend(value);
                    });
                });
                (alu, blu)
            })
            .unzip();
        for alu_events_chunk in alu_events {
            extra.add_alu_events(alu_events_chunk);
        }
        for blu_events_chunk in blu_events {
            extra.add_byte_lookup_events(blu_events_chunk);
        }
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
        cols: &mut MemoryChipValueCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let mut alu_events = HashMap::new();

        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.clk = F::from_canonical_u32(event.clk);

        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        if let Some(record) = event.memory_record {
            cols.memory_access.populate(record, blu_events);
        }

        cols.instruction.populate(event);
        self.populate_memory(cols, event, &mut alu_events, blu_events);

        alu_events
    }

    fn populate_memory(
        &self,
        cols: &mut MemoryChipValueCols<F>,
        event: &CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<AluEvent>>,
        blu_events: &mut impl ByteRecordBehavior,
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
        assert!(aligned_addr.is_multiple_of(4));
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        cols.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));

        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            clk: event.clk,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.b,
            c: event.c,
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
                if cols.most_sig_byte_decomp[7] == F::ONE {
                    cols.mem_value_is_neg_not_x0 =
                        F::from_bool(event.instruction.op_a != (X0 as u32));
                    let sub_event = AluEvent {
                        clk: event.clk,
                        opcode: Opcode::SUB,
                        a: event.a,
                        b: cols.unsigned_mem_val.to_u32(),
                        c: sign_value,
                    };

                    new_alu_events
                        .entry(Opcode::SUB)
                        .and_modify(|op_new_events| op_new_events.push(sub_event))
                        .or_insert(vec![sub_event]);
                }
            }

            // Set the `mem_value_is_pos_not_x0` composite flag.
            cols.mem_value_is_pos_not_x0 = F::from_bool(
                ((matches!(event.instruction.opcode, Opcode::LB | Opcode::LH)
                    && (cols.most_sig_byte_decomp[7] == F::ZERO))
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
            blu_events.add_byte_lookup_event(ByteLookupEvent::new(
                ByteOpcode::U8Range,
                0,
                0,
                byte_pair[0],
                byte_pair[1],
            ));
        }
    }
}

impl<F: Field> MemoryWriteCols<F> {
    pub fn populate(&mut self, record: MemoryWriteRecord, output: &mut impl ByteRecordBehavior) {
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
            .populate_access(current_record, prev_record, output);
    }
}

impl<F: Field> MemoryReadCols<F> {
    pub fn populate(&mut self, record: MemoryReadRecord, output: &mut impl ByteRecordBehavior) {
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
            .populate_access(current_record, prev_record, output);
    }
}

impl<F: Field> MemoryReadWriteCols<F> {
    pub fn populate(&mut self, record: MemoryRecordEnum, output: &mut impl ByteRecordBehavior) {
        match record {
            MemoryRecordEnum::Read(read_record) => self.populate_read(read_record, output),
            MemoryRecordEnum::Write(write_record) => self.populate_write(write_record, output),
        }
    }

    pub fn populate_write(
        &mut self,
        record: MemoryWriteRecord,
        output: &mut impl ByteRecordBehavior,
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
            .populate_access(current_record, prev_record, output);
    }

    pub fn populate_read(
        &mut self,
        record: MemoryReadRecord,
        output: &mut impl ByteRecordBehavior,
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
            .populate_access(current_record, prev_record, output);
    }
}

impl<F: Field> MemoryAccessCols<F> {
    pub(crate) fn populate_access(
        &mut self,
        current_record: MemoryRecord,
        prev_record: MemoryRecord,
        output: &mut impl ByteRecordBehavior,
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

        // Add a range table lookup with the U16 op.
        output.add_u16_range_check(diff_16bit_limb);
        // Add a range table lookup with the U8 op.
        output.add_u8_range_check(diff_8bit_limb as u8, 0);
    }
}
