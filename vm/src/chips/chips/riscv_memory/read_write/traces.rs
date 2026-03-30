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
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_cpu::event::CpuEvent,
            riscv_memory::{
                event::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord},
                read_write::columns::{MemoryChipValueCols, NUM_MEMORY_CHIP_VALUE_COLS},
            },
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            program::Program,
            register::Register::X0,
        },
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::{MEMORY_RW_DATAPAR, WORD_BYTE_SIZE},
};
use hashbrown::HashMap;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

#[inline(always)]
fn encode_memory_trace_clk_u32(value: u64) -> u32 {
    // Stage 0 intentionally retained clk as a u32 proof/event metadata limit for this tranche.
    u32::try_from(value)
        .unwrap_or_else(|_| panic!("cpu event clk 0x{value:016x} does not fit u32 compat boundary"))
}

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
        cols.clk = F::from_canonical_u32(encode_memory_trace_clk_u32(event.clk));

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
                    | Opcode::LWU
                    | Opcode::LD
                    | Opcode::SB
                    | Opcode::SH
                    | Opcode::SW
                    | Opcode::SD
            ),
            "Must be a memory opcode"
        );

        // ---- C1: Address calculation ----
        // Compute full u64 address = b + c (wrapping)
        let memory_addr = event.b.wrapping_add(event.c);
        // addr_word = Word from ALU ADD result (4×u16 limbs)
        cols.addr_word = memory_addr.into();
        let aligned_addr = memory_addr - memory_addr % WORD_BYTE_SIZE as u64;
        cols.addr_aligned = Word::from(aligned_addr);
        assert_eq!(
            cols.addr_aligned[3],
            F::ZERO,
            "memory address must be less than 2^48",
        );

        // Add ALU ADD event
        let add_event = AluEvent {
            clk: event.clk,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.b,
            c: event.c,
            ..Default::default()
        };
        new_alu_events
            .entry(Opcode::ADD)
            .and_modify(|op_new_events| op_new_events.push(add_event))
            .or_insert(vec![add_event]);

        // Stack guard: addr_top_two_limb_inv = 1/(addr[1] + addr[2])
        // Compute limb values directly from the u64 address
        let addr0_u16 = (memory_addr & 0xFFFF) as u16;
        let addr1_u16 = ((memory_addr >> 16) & 0xFFFF) as u16;
        let addr2_u16 = ((memory_addr >> 32) & 0xFFFF) as u16;
        let sum_top = (addr1_u16 as u32) + (addr2_u16 as u32);
        cols.addr_top_two_limb_inv = if sum_top != 0 {
            (F::from_canonical_u32(sum_top)).inverse()
        } else {
            F::ZERO
        };

        // u16 range check: add range check events for addr limbs
        blu_events.add_u16_range_check(addr0_u16);
        blu_events.add_u16_range_check(addr1_u16);
        blu_events.add_u16_range_check(addr2_u16);

        // ---- C2: Offset decomposition ----
        // offset = addr[0] low 3 bits (byte offset within 8-byte slot)
        let addr0_val = memory_addr as u16; // low 16 bits
        let offset = (addr0_val & 0x07) as u8; // low 3 bits
        cols.offset_bit[0] = F::from_bool(offset & 1 != 0);
        cols.offset_bit[1] = F::from_bool(offset & 2 != 0);
        cols.offset_bit[2] = F::from_bool(offset & 4 != 0);

        let bit0 = (offset & 1) as usize;
        let bit1 = ((offset >> 1) & 1) as usize;
        let bit2 = ((offset >> 2) & 1) as usize;
        let limb_index = 2 * bit2 + bit1; // index into 4 u16 limbs

        // Populate one-hot limb_select from (bit1, bit2)
        cols.limb_select = [F::ZERO; 4];
        cols.limb_select[limb_index] = F::ONE;

        // ---- P0-1 trace: byte lookup event for offset_bit binding to addr[0] ----
        // Constraint: looking_byte(BitRange, (addr[0]-offset)/8, 13, 0, is_mem)
        // Trace equivalent: add_bit_range_check((addr0_val - offset) / 8, 13)
        let aligned_div8 = (addr0_val.wrapping_sub(offset as u16)) / 8;
        blu_events.add_bit_range_check(aligned_div8, 13);

        // ---- Memory value as u64 (4×u16 limbs) ----
        // Constraint C5 selects limbs from `memory_access.prev_value()` (the OLD value).
        // For reads: prev_value == value (no change), so either works.
        // For writes: prev_value is the OLD value before the store, which is what the
        // constraint checks against. We must use prev_value here to match.
        let mem_value_u64 = match event.memory_record.unwrap() {
            MemoryRecordEnum::Read(r) => r.value,
            MemoryRecordEnum::Write(w) => w.prev_value,
        };
        let mem_limbs: [u16; 4] = [
            (mem_value_u64 & 0xFFFF) as u16,
            ((mem_value_u64 >> 16) & 0xFFFF) as u16,
            ((mem_value_u64 >> 32) & 0xFFFF) as u16,
            ((mem_value_u64 >> 48) & 0xFFFF) as u16,
        ];

        // ---- C5: Limb selection ----
        let selected_limb = mem_limbs[limb_index];
        cols.selected_limb = F::from_canonical_u16(selected_limb);

        // ---- Load instructions: populate sub-word selection and sign extension ----
        let opcode = event.instruction.opcode;
        let is_load = matches!(
            opcode,
            Opcode::LB
                | Opcode::LBU
                | Opcode::LH
                | Opcode::LHU
                | Opcode::LW
                | Opcode::LWU
                | Opcode::LD
        );

        if is_load {
            match opcode {
                Opcode::LB | Opcode::LBU => {
                    // Split selected_limb into 2 bytes, select one via bit0
                    let low_byte = (selected_limb & 0xFF) as u8;
                    let high_byte = ((selected_limb >> 8) & 0xFF) as u8;
                    cols.selected_limb_low_byte = F::from_canonical_u8(low_byte);
                    let selected_byte = if bit0 == 1 { high_byte } else { low_byte };
                    cols.selected_byte = F::from_canonical_u8(selected_byte);

                    // Range check for selected_limb_low_byte
                    blu_events.add_u8_range_check(low_byte, 0);

                    // unsigned_mem_val = [selected_byte, 0, 0, 0]
                    cols.unsigned_mem_val = Word([
                        F::from_canonical_u8(selected_byte),
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                    ]);

                    // MSB = bit7 of selected_byte (only for signed LB, not LBU)
                    let msb = if opcode == Opcode::LB {
                        (selected_byte >> 7) & 1
                    } else {
                        0 // LBU: constraint forces msb=0
                    };
                    cols.msb = F::from_canonical_u8(msb);

                    // ---- P0-2 trace: msb verification byte lookup event for LB ----
                    // Constraint: looking_byte(MSB, msb, selected_byte, 0, is_lb)
                    // TODO(P0-2): Verify ByteOpcode::MSB event format matches byte chip's
                    //   looked_byte(MSB, a1=msb, b=selected_byte, c=0) expectations.
                    if opcode == Opcode::LB {
                        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
                            ByteOpcode::MSB,
                            msb as u16,    // a1 = msb result
                            0,             // a2 = 0
                            selected_byte, // b = byte value
                            0,             // c = 0
                        ));
                    }

                    // Sign extension for LB (not LBU)
                    if opcode == Opcode::LB && msb == 1 && event.instruction.op_a != (X0 as u8) {
                        cols.mem_value_is_neg_not_x0 = F::ONE;
                        // op_a is set by instruction.populate already
                    }
                }
                Opcode::LH | Opcode::LHU => {
                    // selected_limb is already the u16 we want
                    // unsigned_mem_val = [selected_limb, 0, 0, 0]
                    cols.unsigned_mem_val = Word([
                        F::from_canonical_u16(selected_limb),
                        F::ZERO,
                        F::ZERO,
                        F::ZERO,
                    ]);

                    // MSB = bit15 of selected_limb (only for signed LH, not LHU)
                    let msb = if opcode == Opcode::LH {
                        (selected_limb >> 15) & 1
                    } else {
                        0 // LHU: constraint forces msb=0
                    };
                    cols.msb = F::from_canonical_u16(msb);

                    // ---- P0-2 trace: U16MSBOperation byte lookup event for LH ----
                    // Constraint: looking_byte(U16Range, 2*selected_limb - msb*2^16, 0, 0, is_lh)
                    if opcode == Opcode::LH {
                        let diff = (selected_limb as u32) * 2 - (msb as u32) * 65536;
                        blu_events.add_u16_range_check(diff as u16);
                    }

                    // Sign extension for LH (not LHU)
                    if opcode == Opcode::LH && msb == 1 && event.instruction.op_a != (X0 as u8) {
                        cols.mem_value_is_neg_not_x0 = F::ONE;
                    }
                }
                Opcode::LW | Opcode::LWU => {
                    // selected_word = 2 limbs based on bit2
                    let sw0 = if bit2 == 0 {
                        mem_limbs[0]
                    } else {
                        mem_limbs[2]
                    };
                    let sw1 = if bit2 == 0 {
                        mem_limbs[1]
                    } else {
                        mem_limbs[3]
                    };
                    cols.selected_word = [F::from_canonical_u16(sw0), F::from_canonical_u16(sw1)];

                    // unsigned_mem_val = [word[0], word[1], 0, 0]
                    cols.unsigned_mem_val = Word([
                        F::from_canonical_u16(sw0),
                        F::from_canonical_u16(sw1),
                        F::ZERO,
                        F::ZERO,
                    ]);

                    // MSB = bit15 of selected_word[1] (only for signed LW, not LWU)
                    let msb = if opcode == Opcode::LW {
                        (sw1 >> 15) & 1
                    } else {
                        0 // LWU: constraint forces msb=0
                    };
                    cols.msb = F::from_canonical_u16(msb);

                    // ---- P0-2 trace: U16MSBOperation byte lookup event for LW ----
                    // Constraint: looking_byte(U16Range, 2*selected_word[1] - msb*2^16, 0, 0, is_lw)
                    if opcode == Opcode::LW {
                        let diff = (sw1 as u32) * 2 - (msb as u32) * 65536;
                        blu_events.add_u16_range_check(diff as u16);
                    }

                    // Sign extension for LW (not LWU) — LW is signed in RV64
                    if opcode == Opcode::LW && msb == 1 && event.instruction.op_a != (X0 as u8) {
                        cols.mem_value_is_neg_not_x0 = F::ONE;
                    }
                }
                Opcode::LD => {
                    // unsigned_mem_val = full mem_val (all 4 limbs)
                    cols.unsigned_mem_val = mem_value_u64.into();
                    // No sign extension for LD
                    cols.msb = F::ZERO;
                }
                _ => unreachable!(),
            }

            // Set mem_value_is_pos_not_x0 composite flag
            let is_signed = matches!(opcode, Opcode::LB | Opcode::LH | Opcode::LW);
            let msb_is_one = cols.msb == F::ONE;
            let not_x0 = event.instruction.op_a != (X0 as u8);
            cols.mem_value_is_pos_not_x0 = F::from_bool(!(is_signed && msb_is_one) && not_x0);
        }

        // ---- Store instructions: populate store_value with increment pattern ----
        let is_store = matches!(opcode, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD);
        if is_store {
            let a_val_u64 = event.a;
            let a_limbs: [u16; 4] = [
                (a_val_u64 & 0xFFFF) as u16,
                ((a_val_u64 >> 16) & 0xFFFF) as u16,
                ((a_val_u64 >> 32) & 0xFFFF) as u16,
                ((a_val_u64 >> 48) & 0xFFFF) as u16,
            ];

            // prev_mem_val is in memory_access.prev_value, which was populated above
            let prev_value_u64 = event
                .memory_record
                .map(|r| match r {
                    MemoryRecordEnum::Write(w) => w.prev_value,
                    MemoryRecordEnum::Read(r) => r.value,
                })
                .unwrap_or(0);
            let prev_limbs: [u16; 4] = [
                (prev_value_u64 & 0xFFFF) as u16,
                ((prev_value_u64 >> 16) & 0xFFFF) as u16,
                ((prev_value_u64 >> 32) & 0xFFFF) as u16,
                ((prev_value_u64 >> 48) & 0xFFFF) as u16,
            ];

            match opcode {
                Opcode::SB => {
                    let target_limb = limb_index;
                    let old_limb = prev_limbs[target_limb];
                    let old_low_byte = (old_limb & 0xFF) as u8;
                    let old_high_byte = ((old_limb >> 8) & 0xFF) as u8;
                    let reg_low_byte = (a_limbs[0] & 0xFF) as u8;
                    let reg_high_byte = ((a_limbs[0] >> 8) & 0xFF) as u8;

                    cols.register_low_byte = F::from_canonical_u8(reg_low_byte);
                    cols.mem_limb_low_byte = F::from_canonical_u8(old_low_byte);
                    cols.selected_limb_low_byte = F::from_canonical_u8(old_low_byte);

                    // Compute increment
                    let increment: i32 = if bit0 == 0 {
                        (reg_low_byte as i32) - (old_low_byte as i32)
                    } else {
                        (reg_low_byte as i32) * 256 - (old_limb as i32) + (old_low_byte as i32)
                    };
                    // Store as field element (handles negative via modular arithmetic)
                    cols.increment = if increment >= 0 {
                        F::from_canonical_u32(increment as u32)
                    } else {
                        -F::from_canonical_u32((-increment) as u32)
                    };

                    // store_value = prev + increment at target limb
                    let mut sv = prev_limbs;
                    let new_limb_val = (prev_limbs[target_limb] as i32 + increment) as u16;
                    sv[target_limb] = new_limb_val;
                    cols.store_value = Word(sv.map(|v| F::from_canonical_u16(v)));

                    // ---- P0-3 trace: SB byte-split range check events ----
                    // Constraint: looking_rangecheck(U8Range, 0, 0, reg_low_byte, reg_high_byte, is_sb)
                    blu_events.add_u8_range_check(reg_low_byte, reg_high_byte);
                    // Constraint: looking_rangecheck(U8Range, 0, 0, mem_low_byte, mem_high_byte, is_sb)
                    blu_events.add_u8_range_check(old_low_byte, old_high_byte);
                }
                Opcode::SH => {
                    // store_limb = a_limbs[0], replaces at limb_index
                    let mut sv = prev_limbs;
                    sv[limb_index] = a_limbs[0];
                    cols.store_value = Word(sv.map(|v| F::from_canonical_u16(v)));
                }
                Opcode::SW => {
                    // Replace 2 limbs based on bit2
                    let mut sv = prev_limbs;
                    if bit2 == 0 {
                        sv[0] = a_limbs[0];
                        sv[1] = a_limbs[1];
                    } else {
                        sv[2] = a_limbs[0];
                        sv[3] = a_limbs[1];
                    }
                    cols.store_value = Word(sv.map(|v| F::from_canonical_u16(v)));
                }
                Opcode::SD => {
                    // Complete write
                    cols.store_value = a_val_u64.into();
                }
                _ => unreachable!(),
            }
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
            u64::from(prev_record.timestamp)
        } else {
            u64::from(prev_record.chunk)
        };
        let current_time_value = if use_clk_comparison {
            u64::from(current_record.timestamp)
        } else {
            u64::from(current_record.chunk)
        };

        let diff_minus_one = current_time_value - prev_time_value - 1;
        let diff_16bit_limb = (diff_minus_one & 0xffff) as u16;
        self.diff_16bit_limb = F::from_canonical_u16(diff_16bit_limb);
        let diff_8bit_limb = ((diff_minus_one >> 16) & 0xff) as u32;
        self.diff_8bit_limb = F::from_canonical_u32(diff_8bit_limb);

        // Add a range table lookup with the U16 op.
        output.add_u16_range_check(diff_16bit_limb);
        // Add a range table lookup with the U8 op.
        output.add_u8_range_check(diff_8bit_limb as u8, 0);
    }
}

impl<F> EventCapture for MemoryReadWriteChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        let num_memory_rw_events = record.memory_read_write_event_indices.len();
        if num_memory_rw_events == 0 {
            return;
        }
        event_counter.num_memory_read_writes += num_memory_rw_events;
        // Use references to avoid copying CpuEvent values
        let memory_rw_events: Vec<&CpuEvent> = record
            .memory_read_write_event_indices
            .iter()
            .copied()
            .map(|i| &record.cpu_events[i])
            .collect();

        // Use efficient parallel processing similar to CPU chip
        let chunk_size = std::cmp::max(num_memory_rw_events / num_cpus::get(), 1);
        let memory_rw_counts: Vec<usize> = memory_rw_events
            .pico_chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk
                    .iter()
                    .map(|event| Self::count_memory_read_write_events(event))
            })
            .collect();

        // Sum sub events efficiently
        let num_add_sub = memory_rw_counts.iter().sum::<usize>();
        event_counter.num_add_events += num_add_sub;
    }
}

impl<F> MemoryReadWriteChip<F> {
    /// Count ALU events generated per memory instruction.
    /// With direct limb fill sign extension (no ALU SUB), each instruction generates exactly 1 ADD event.
    fn count_memory_read_write_events(_event: &CpuEvent) -> usize {
        1
    }
}
