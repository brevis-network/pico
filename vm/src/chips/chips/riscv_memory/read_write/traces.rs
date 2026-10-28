use super::{
    columns::{
        MemoryAccessCols, MemoryAccessLiteCols, MemoryReadCols, MemoryReadLiteCols,
        MemoryReadWriteCols, MemoryReadWriteLiteCols, MemoryWriteCols, NUM_MEMORY_CHIP_COLS,
    },
    MemoryReadWriteChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_cpu::event::CpuEvent,
            riscv_memory::{
                event::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord},
                read_write::columns::{MemoryChipValueCols, NUM_MEMORY_CHIP_VALUE_COLS},
            },
        },
        ffi::FfiOption,
        utils::next_power_of_two,
    },
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::MEMORY_RW_DATAPAR,
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_memory_read_write_generate_extra_record_and_main_u64,
    cuda_memory_read_write_generate_extra_record_and_main_u64_packed,
};
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use tracing::info;

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
            .as_slice()
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
            .as_slice()
            .iter()
            .filter(|e| e.instruction.is_memory_instruction())
            .collect::<Box<[_]>>();
        // Generate the trace rows for each event. The only extra records are byte lookups: the
        // address addition is proven in-chip, so no ALU ADD event is dispatched.
        let chunk_size = std::cmp::max(mem_events.len() / num_cpus::get(), 1);
        let blu_events: Vec<Vec<ByteLookupEvent>> = mem_events
            .pico_chunks(chunk_size)
            .map(|ops: &[&CpuEvent]| {
                let mut blu: Vec<ByteLookupEvent> = Vec::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_MEMORY_CHIP_VALUE_COLS];
                    let cols: &mut MemoryChipValueCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(op, cols, &mut blu);
                });
                blu
            })
            .collect();
        for blu_events_chunk in blu_events {
            extra.add_byte_lookup_events(blu_events_chunk);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        record
            .cpu_events
            .as_slice()
            .iter()
            .any(|e| e.instruction.is_memory_instruction())
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for MemoryReadWriteChip<F> {
    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        // The address addition is proven in-chip, so memory instructions dispatch no ALU event;
        // this chip only contributes its own row count.
        let num_memory_rw_events = record.memory_read_write_event_indices.len();
        if num_memory_rw_events == 0 {
            return;
        }
        counter.num_memory_read_writes = num_memory_rw_events;
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_memory_read_writes > 0
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        // Get memory events using indices to avoid duplication
        let event_size = input.memory_read_write_event_indices.len();

        let nrows = event_size.div_ceil(MEMORY_RW_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = next_power_of_two(nrows, log2_nrows);

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let mut d_event_indices =
            DevicePoolAllocation::<usize>::alloc_from_pool_async(event_size, mem_pool, stream)
                .unwrap();
        // MLE_PACKED_EVENTS: the index array rides the pinned staging (same bytes).
        let packed_stage = prepared_gpu_events.packed.as_deref();
        let event_indices_src: *const std::ffi::c_void = match packed_stage {
            Some(pk) if pk.mem_event_indices().len() == event_size => {
                pk.mem_event_indices().as_ptr() as *const _
            }
            _ => input.memory_read_write_event_indices.as_c_void_ptr(),
        };
        unsafe {
            let _ = cudaMemcpyAsync(
                d_event_indices.as_mut_c_void_ptr(),
                event_indices_src,
                event_size * size_of::<usize>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let trace_size = padded_nrows * NUM_MEMORY_CHIP_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let d_cpu_events = preallocated_gpu_memory.d_cpu_events.as_mut().unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

        if let Some(packed) = prepared_gpu_events.packed.as_deref() {
            // MLE_PACKED_EVENTS: d_cpu_events holds the 80B packed stream; the memory_record
            // side stream is dense in exactly this chip's event_indices order.
            use crate::instances::preparer::{MemRecordPacked, PACKED_EVENT_FORMAT_V1};
            let mem_src = packed.mem_records();
            assert_eq!(
                mem_src.len(),
                event_size,
                "packed mem side-stream length mismatch"
            );
            let mut d_mem_records = DevicePoolAllocation::<MemRecordPacked>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_mem_records.as_mut_c_void_ptr(),
                    mem_src.as_ptr() as *const _,
                    event_size * size_of::<MemRecordPacked>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
                let err = cuda_memory_read_write_generate_extra_record_and_main_u64_packed(
                    NUM_MEMORY_CHIP_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_cpu_events.as_ptr() as *const _,
                    d_mem_records.as_ptr() as *const _,
                    packed.chunk as usize,
                    d_event_indices.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_byte_trace.as_mut_ptr() as *mut _,
                    PACKED_EVENT_FORMAT_V1,
                );
                assert_eq!(
                    err.code, 0,
                    "cuda_memory_read_write_generate_extra_record_and_main_u64_packed failed (packed format mismatch?)"
                );
            }
        } else {
            unsafe {
                cuda_memory_read_write_generate_extra_record_and_main_u64(
                    NUM_MEMORY_CHIP_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_cpu_events.as_ptr() as *const _,
                    d_event_indices.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    d_byte_trace.as_mut_ptr() as *mut _,
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[memory-rw-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_MEMORY_CHIP_COLS, d_trace)
    }
}

impl<F: Field> MemoryReadWriteChip<F> {
    fn event_to_row(
        &self,
        event: &CpuEvent,
        cols: &mut MemoryChipValueCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) {
        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(encode_memory_trace_clk_u32(event.clk));

        // Populate memory accesses for reading from memory.
        assert_eq!(
            matches!(event.memory_record, FfiOption::Some(_)),
            matches!(event.memory, FfiOption::Some(_))
        );
        if let FfiOption::Some(record) = event.memory_record {
            cols.memory_access.populate(record, blu_events);
        }

        cols.instruction.populate(event);
        self.populate_memory(cols, event, blu_events);
    }

    fn populate_memory(
        &self,
        cols: &mut MemoryChipValueCols<F>,
        event: &CpuEvent,
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
        // `addr_word` holds only the low 2 u16 limbs of the sum; the addition is proven
        // in-chip by a carry chain whose 3rd and 4th result limbs are literal 0s (fail-closed for
        // addr >= 2^32), so no ALU ADD event is dispatched for it. The bound is asserted here so
        // that an out-of-range address fails loudly at trace generation instead of producing an
        // unprovable trace (alignment only clears the low 3 bits of limb 0, so it is checked on
        // the raw address).
        assert!(
            memory_addr < (1u64 << 32),
            "memory address must be less than 2^32",
        );
        cols.addr_word = [
            F::from_u16((memory_addr & 0xFFFF) as u16),
            F::from_u16(((memory_addr >> 16) & 0xFFFF) as u16),
        ];

        // Stack guard: addr_limb1_inv = 1/addr[1]
        let addr1_u16 = ((memory_addr >> 16) & 0xFFFF) as u16;
        // The AIR U16Range-checks addr_word[1] in-chip (count is_mem); limb 0 is bounded by the
        // BitRange(13) offset lookup below and gets no event of its own.
        blu_events.add_u16_range_check(addr1_u16);
        cols.addr_limb1_inv = if addr1_u16 != 0 {
            F::from_u16(addr1_u16).inverse()
        } else {
            F::ZERO
        };

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
        // Index into the 4 u16 limbs. The one-hot limb selector is not committed: the AIR forms
        // it from the offset bits.
        let limb_index = 2 * bit2 + bit1;

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
        let memory_record = if let FfiOption::Some(record) = event.memory_record {
            record
        } else {
            unreachable!("memory_record should be Some for memory instructions")
        };
        let mem_value_u64 = match memory_record {
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
        cols.selected_limb = F::from_u16(selected_limb);

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
                    // Split selected_limb into 2 bytes, select one via bit0. The low byte goes
                    // into `mem_limb_low_byte`, the slot the SB rows use for the same split of
                    // the memory limb they modify.
                    let low_byte = (selected_limb & 0xFF) as u8;
                    let high_byte = ((selected_limb >> 8) & 0xFF) as u8;
                    let selected_byte = if bit0 == 1 { high_byte } else { low_byte };
                    cols.selected_byte = F::from_u8(selected_byte);
                    cols.mem_limb_low_byte = F::from_u8(low_byte);

                    // The memory-limb split U8Range lookup (shared with SB rows): (low, high) of
                    // selected_limb. LBU bounds the high byte nowhere else.
                    blu_events.add_u8_range_check(low_byte, high_byte);

                    // MSB = bit7 of selected_byte (only for signed LB, not LBU)
                    let msb = if opcode == Opcode::LB {
                        (selected_byte >> 7) & 1
                    } else {
                        0 // LBU: constraint forces msb=0
                    };
                    cols.msb = F::from_u8(msb);

                    // LB rides the LH/LW U16MSB lookup: `lhw_val = 256 * selected_byte` and the
                    // operand `2 * lhw_val - msb * 2^16 = 512 * byte - msb * 2^16` is a u16
                    // exactly when `msb` is the byte's bit 7.
                    if opcode == Opcode::LB {
                        let lhw = 256 * u16::from(selected_byte);
                        cols.lhw_val = F::from_u16(lhw);
                        let diff = (lhw as u32) * 2 - (msb as u32) * 65536;
                        blu_events.add_u16_range_check(diff as u16);
                    }
                }
                Opcode::LH | Opcode::LHU => {
                    // selected_limb is already the u16 we want

                    // MSB = bit15 of selected_limb (only for signed LH, not LHU)
                    let msb = if opcode == Opcode::LH {
                        (selected_limb >> 15) & 1
                    } else {
                        0 // LHU: constraint forces msb=0
                    };
                    cols.msb = F::from_u16(msb);

                    // U16MSB event for LH (the lookup is shared with LW and LB).
                    // Shared LH/LW/LB mux operand.
                    cols.lhw_val = F::from_u16(selected_limb);
                    if opcode == Opcode::LH {
                        let diff = (selected_limb as u32) * 2 - (msb as u32) * 65536;
                        blu_events.add_u16_range_check(diff as u16);
                    }
                }
                Opcode::LW | Opcode::LWU => {
                    // The selected word is `[selected_limb, sw1]` with sw1 chosen by bit2 (word
                    // alignment makes bit1 = 0, so `selected_limb` already is the low half).
                    let sw1 = if bit2 == 0 {
                        mem_limbs[1]
                    } else {
                        mem_limbs[3]
                    };

                    // MSB = bit15 of the high half (only for signed LW, not LWU)
                    let msb = if opcode == Opcode::LW {
                        (sw1 >> 15) & 1
                    } else {
                        0 // LWU: constraint forces msb=0
                    };
                    cols.msb = F::from_u16(msb);

                    // U16MSB event for LW (the lookup is shared with LH and LB).
                    // Shared LH/LW/LB mux operand; the AIR pins it on LWU rows too (it is the
                    // limb-1 load value there), so it is written on both variants.
                    cols.lhw_val = F::from_u16(sw1);
                    if opcode == Opcode::LW {
                        let diff = (sw1 as u32) * 2 - (msb as u32) * 65536;
                        blu_events.add_u16_range_check(diff as u16);
                    }
                }
                Opcode::LD => {
                    // No sign extension for LD
                    cols.msb = F::ZERO;
                }
                _ => unreachable!(),
            }
        }

        // ---- Store instructions ----
        // `store_value` is de-materialized; the unified store equation is asserted directly
        // on `memory_access.value()`, which was populated from the memory record above. SB
        // needs the byte split plus `shift` (the byte increment), SH needs only `shift` (the
        // limb replacement); SW/SD need no extra witnesses and leave `shift` at zero, as its
        // ungated definition requires.
        if opcode == Opcode::SB {
            let a_limb0 = (event.a & 0xFFFF) as u16;

            // prev_mem_val is in memory_access.prev_value, which was populated above
            let prev_value_u64 = match memory_record {
                MemoryRecordEnum::Write(w) => w.prev_value,
                MemoryRecordEnum::Read(r) => r.value,
            };
            let old_limb = ((prev_value_u64 >> (16 * limb_index)) & 0xFFFF) as u16;
            let old_low_byte = (old_limb & 0xFF) as u8;
            let old_high_byte = ((old_limb >> 8) & 0xFF) as u8;
            let reg_low_byte = (a_limb0 & 0xFF) as u8;
            let reg_high_byte = ((a_limb0 >> 8) & 0xFF) as u8;

            cols.register_low_byte = F::from_u8(reg_low_byte);
            cols.mem_limb_low_byte = F::from_u8(old_low_byte);

            // The byte increment, which is the SB row's `shift`
            let increment: i32 = if bit0 == 0 {
                (reg_low_byte as i32) - (old_low_byte as i32)
            } else {
                (reg_low_byte as i32) * 256 - (old_limb as i32) + (old_low_byte as i32)
            };
            // Store as field element (handles negative via modular arithmetic)
            cols.shift = if increment >= 0 {
                F::from_u32(increment as u32)
            } else {
                -F::from_u32((-increment) as u32)
            };

            // ---- P0-3 trace: SB byte-split range check events ----
            // Constraint: looking_rangecheck(U8Range, 0, 0, reg_low_byte, reg_high_byte, is_sb)
            blu_events.add_u8_range_check(reg_low_byte, reg_high_byte);
            // Constraint: looking_rangecheck(U8Range, 0, 0, mem_low_byte, mem_high_byte,
            //                                is_sb + is_lb + is_lbu)
            blu_events.add_u8_range_check(old_low_byte, old_high_byte);
        } else if opcode == Opcode::SH {
            // The SH row's `shift` is the limb replacement `op_a[0] - selected_limb`, a
            // field-negative value whenever the stored half-word is below the old one.
            let a_limb0 = (event.a & 0xFFFF) as u16;
            cols.shift = F::from_u16(a_limb0) - F::from_u16(selected_limb);
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

/// The timestamp half of an access row, shared by the full and the lite layouts: the in-chunk
/// predecessor clk and the 16 + 9 limbs of `clk - prev_clk - 1`, with their two byte-table events.
///
/// Returns `(prev_clk, diff_16bit_limb, diff_hi9)`.
fn populate_timestamp_diff(
    current_record: MemoryRecord,
    prev_record: MemoryRecord,
    output: &mut impl ByteRecordBehavior,
) -> (u32, u16, u16) {
    // The predecessor named here is always in this chunk. When the address was last touched
    // in an *earlier* chunk there is no in-chunk timestamp to name, so the sentinel 0 stands
    // in — the same label `MemoryLocalChip` puts on the state the chunk inherits, which is
    // what makes the two sides of the memory bus meet. `CHUNK_CLK_START` keeps every real
    // access above the sentinel, so it can never collide with one.
    let prev_clk = if prev_record.chunk == current_record.chunk {
        prev_record.timestamp
    } else {
        0
    };

    // The comparison is unconditionally on `clk` now: same chunk by construction.
    let diff_minus_one = u64::from(current_record.timestamp) - u64::from(prev_clk) - 1;
    // 25-bit decomposition (16 + 9): diffs can span the whole chunk-clk range. Assert
    // instead of silently truncating.
    assert!(
        diff_minus_one < (1 << 25),
        "memory timestamp diff {diff_minus_one} exceeds the 25-bit budget"
    );
    let diff_16bit_limb = (diff_minus_one & 0xffff) as u16;
    let diff_hi9 = ((diff_minus_one >> 16) & 0x1ff) as u16;

    // Add a range table lookup with the U16 op.
    output.add_u16_range_check(diff_16bit_limb);
    // Range check the merged high limb to 9 bits (BitRange table).
    output.add_bit_range_check(diff_hi9, 9);

    (prev_clk, diff_16bit_limb, diff_hi9)
}

impl<F: Field> MemoryAccessCols<F> {
    pub(crate) fn populate_access(
        &mut self,
        current_record: MemoryRecord,
        prev_record: MemoryRecord,
        output: &mut impl ByteRecordBehavior,
    ) {
        self.value = current_record.value.into();

        let (prev_clk, diff_16bit_limb, diff_hi9) =
            populate_timestamp_diff(current_record, prev_record, output);
        self.prev_clk = F::from_u32(prev_clk);
        self.diff_16bit_limb = F::from_u16(diff_16bit_limb);
        self.diff_hi9 = F::from_u16(diff_hi9);
    }
}

impl<F: Field> MemoryReadLiteCols<F> {
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

impl<F: Field> MemoryReadWriteLiteCols<F> {
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

impl<F: Field> MemoryAccessLiteCols<F> {
    /// Same as [`MemoryAccessCols::populate_access`] minus the `prev_clk` column: the
    /// predecessor clk is computed only to take the difference from, and the AIR rebuilds it
    /// from the two committed limbs.
    pub(crate) fn populate_access(
        &mut self,
        current_record: MemoryRecord,
        prev_record: MemoryRecord,
        output: &mut impl ByteRecordBehavior,
    ) {
        self.value = current_record.value.into();

        let (_prev_clk, diff_16bit_limb, diff_hi9) =
            populate_timestamp_diff(current_record, prev_record, output);
        self.diff_16bit_limb = F::from_u16(diff_16bit_limb);
        self.diff_hi9 = F::from_u16(diff_hi9);
    }
}

impl<F> EventCapture for MemoryReadWriteChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        // No extra records: the address addition is proven in-chip (see the `ChipBehavior`
        // `count_extra_records`).
        event_counter.num_memory_read_writes += record.memory_read_write_event_indices.len();
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_memory_trace_clk_u32, MemoryReadWriteChip};
    use crate::{
        chips::{
            chips::{
                byte::event::ByteLookupEvent,
                riscv_cpu::event::CpuEvent,
                riscv_memory::{
                    event::{MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord},
                    read_write::columns::MemoryChipValueCols,
                },
            },
            ffi::FfiOption,
        },
        compiler::{
            riscv::{
                instruction::Instruction,
                opcode::{ByteOpcode, Opcode},
            },
            word::Word,
        },
    };
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_koala_bear::KoalaBear;

    fn decode_word<F: PrimeField32>(word: Word<F>) -> u64 {
        (word[0].as_canonical_u32() as u64)
            | ((word[1].as_canonical_u32() as u64) << 16)
            | ((word[2].as_canonical_u32() as u64) << 32)
            | ((word[3].as_canonical_u32() as u64) << 48)
    }

    #[test]
    fn memory_trace_clk_encoding_accepts_u32_range() {
        assert_eq!(encode_memory_trace_clk_u32(u32::MAX as u64), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "does not fit u32 compat boundary")]
    fn memory_trace_clk_encoding_rejects_overflow() {
        let _ = encode_memory_trace_clk_u32(u64::from(u32::MAX) + 1);
    }

    /// `addr_word` has two limbs, so an address at or above 2^32 has no row; trace generation
    /// refuses it instead of producing an unprovable trace.
    #[test]
    #[should_panic(expected = "memory address must be less than 2^32")]
    fn event_to_row_rejects_an_address_at_or_above_2_32() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let value = 0u64;
        let event = CpuEvent {
            chunk: 1,
            clk: 7,
            instruction: Instruction::new(Opcode::LD, 12, 10, 0, false, true),
            b: 1u64 << 32,
            c: 0,
            memory: FfiOption::Some(value),
            memory_record: FfiOption::Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value,
                chunk: 1,
                timestamp: 7,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };

        let mut cols = MemoryChipValueCols::default();
        let mut blu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&event, &mut cols, &mut blu_events);
    }

    #[test]
    fn event_to_row_preserves_full_u64_for_ld_reads() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let value = 0xDEAD_BEEF_CAFE_BABEu64;
        let event = CpuEvent {
            chunk: 1,
            clk: 7,
            instruction: Instruction::new(Opcode::LD, 12, 10, 0, false, true),
            b: 0x20000,
            c: 0,
            memory: FfiOption::Some(value),
            memory_record: FfiOption::Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value,
                chunk: 1,
                timestamp: 7,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };

        let mut cols = MemoryChipValueCols::default();
        let mut blu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&event, &mut cols, &mut blu_events);

        assert_eq!(decode_word(cols.memory_access.access.value), value);
        // `unsigned_mem_val` is de-materialized; the committed access value is the
        // only per-row word carrying the full 64-bit LD payload.
        assert_eq!(decode_word(cols.memory_access.prev_value), value);
    }

    #[test]
    fn event_to_row_preserves_upper_half_for_sw_at_offset_four() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let prev_value = 0x1122_3344_5566_7788u64;
        let new_word = 0xA1B2_C3D4u64;
        let event = CpuEvent {
            chunk: 1,
            clk: 9,
            instruction: Instruction::new(Opcode::SW, 11, 10, 4, false, true),
            a: new_word,
            b: 0x20000,
            c: 4,
            memory: FfiOption::Some(0xA1B2_C3D4_5566_7788u64),
            memory_record: FfiOption::Some(MemoryRecordEnum::Write(MemoryWriteRecord {
                value: 0xA1B2_C3D4_5566_7788u64,
                chunk: 1,
                timestamp: 9,
                prev_value,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };

        let mut cols = MemoryChipValueCols::default();
        let mut blu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&event, &mut cols, &mut blu_events);

        assert_eq!(decode_word(cols.memory_access.prev_value), prev_value);
        // `store_value` is de-materialized; the committed post-store access value
        // carries the merged word.
        assert_eq!(
            decode_word(cols.memory_access.access.value),
            0xA1B2_C3D4_5566_7788u64
        );
        // SW rows leave the sub-limb shift at zero (ungated definition).
        assert_eq!(cols.shift, KoalaBear::ZERO);
    }

    /// LWU rows write `lhw_val` on the shared LW/LWU arm: the AIR pins it there as the limb-1
    /// load value on LWU as well as LW, and `msb` must be zero on the unsigned load.
    #[test]
    fn event_to_row_lwu_pins_lhw_val_to_the_high_half() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let value = 0xDEAD_BEEF_CAFE_BABEu64;
        let event = CpuEvent {
            chunk: 1,
            clk: 11,
            instruction: Instruction::new(Opcode::LWU, 12, 10, 4, false, true),
            a: 0xDEAD_BEEF,
            b: 0x20000,
            c: 4,
            memory: FfiOption::Some(value),
            memory_record: FfiOption::Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value,
                chunk: 1,
                timestamp: 11,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };

        let mut cols = MemoryChipValueCols::default();
        let mut blu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&event, &mut cols, &mut blu_events);

        // Offset 4: bit2 = 1, so the selected word is limbs 2 and 3.
        assert_eq!(cols.selected_limb, KoalaBear::from_u16(0xBEEF));
        assert_eq!(cols.lhw_val, KoalaBear::from_u16(0xDEAD));
        assert_eq!(cols.msb, KoalaBear::ZERO);
        assert_eq!(cols.shift, KoalaBear::ZERO);
    }

    /// SH rows write `shift = op_a[0] - selected_limb`, which is field-negative when the stored
    /// half-word is below the one it replaces.
    #[test]
    fn event_to_row_sh_writes_the_limb_shift() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let prev_value = 0x1122_3344_5566_7788u64;
        let new_value = 0x1122_3344_1234_7788u64;
        let event = CpuEvent {
            chunk: 1,
            clk: 13,
            instruction: Instruction::new(Opcode::SH, 11, 10, 2, false, true),
            a: 0x1234,
            b: 0x20000,
            c: 2,
            memory: FfiOption::Some(new_value),
            memory_record: FfiOption::Some(MemoryRecordEnum::Write(MemoryWriteRecord {
                value: new_value,
                chunk: 1,
                timestamp: 13,
                prev_value,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };

        let mut cols = MemoryChipValueCols::default();
        let mut blu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&event, &mut cols, &mut blu_events);

        // Offset 2: bit1 = 1, so limb 1 (0x5566) is replaced by the register's low half.
        assert_eq!(cols.selected_limb, KoalaBear::from_u16(0x5566));
        assert_eq!(
            cols.shift,
            KoalaBear::from_u16(0x1234) - KoalaBear::from_u16(0x5566)
        );
        assert_eq!(decode_word(cols.memory_access.access.value), new_value);
    }

    /// LB rows emit exactly one U8Range event, `(low, high)` of the selected limb, matching the
    /// memory-limb split lookup they share with SB rows; the low byte lives in
    /// `mem_limb_low_byte`. The sign bit rides the U16MSB lookup through `lhw_val = 256 * byte`.
    #[test]
    fn event_to_row_lb_emits_one_u8_range_event() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let value = 0xDEAD_BEEF_CAFE_BABEu64;
        let event = CpuEvent {
            chunk: 1,
            clk: 15,
            instruction: Instruction::new(Opcode::LB, 12, 10, 1, false, true),
            a: 0xFFFF_FFFF_FFFF_FFBA,
            b: 0x20000,
            c: 1,
            memory: FfiOption::Some(value),
            memory_record: FfiOption::Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value,
                chunk: 1,
                timestamp: 15,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };

        let mut cols = MemoryChipValueCols::default();
        let mut blu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&event, &mut cols, &mut blu_events);

        // Offset 1: limb 0 (0xBABE), high byte selected.
        assert_eq!(cols.mem_limb_low_byte, KoalaBear::from_u8(0xBE));
        assert_eq!(cols.register_low_byte, KoalaBear::ZERO);
        assert_eq!(cols.selected_byte, KoalaBear::from_u8(0xBA));
        assert_eq!(cols.msb, KoalaBear::ONE);
        assert_eq!(cols.lhw_val, KoalaBear::from_u16(256 * 0xBA));
        let u8_events: Vec<_> = blu_events
            .iter()
            .filter(|e| e.opcode == ByteOpcode::U8Range)
            .collect();
        assert_eq!(
            u8_events,
            vec![&ByteLookupEvent::new(ByteOpcode::U8Range, 0, 0, 0xBE, 0xBA)]
        );
        // The U16MSB operand `2 * lhw_val - msb * 2^16 = 512 * 0xBA - 65536 = 0x7400`; a U16Range
        // event carries the value as its two bytes `(b, c) = (0x74, 0x00)`.
        assert!(blu_events.contains(&ByteLookupEvent::new(
            ByteOpcode::U16Range,
            0,
            0,
            0x74,
            0x00
        )));
        assert!(blu_events.iter().all(|e| e.opcode != ByteOpcode::MSB));
    }

    /// LBU rows have no sign bit: `msb = 0`, `lhw_val` stays 0 (the LB definition is gated on
    /// `is_lb`) and the row emits one U16Range event fewer than the LB row of the same access.
    #[test]
    fn event_to_row_lbu_leaves_the_sign_operand_zero() {
        let chip = MemoryReadWriteChip::<KoalaBear>::default();
        let value = 0xDEAD_BEEF_CAFE_BABEu64;
        let mk = |opcode: Opcode| CpuEvent {
            chunk: 1,
            clk: 15,
            instruction: Instruction::new(opcode, 12, 10, 1, false, true),
            a: if opcode == Opcode::LB {
                0xFFFF_FFFF_FFFF_FFBA
            } else {
                0xBA
            },
            b: 0x20000,
            c: 1,
            memory: FfiOption::Some(value),
            memory_record: FfiOption::Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value,
                chunk: 1,
                timestamp: 15,
                prev_chunk: 0,
                prev_timestamp: 0,
            })),
            ..Default::default()
        };
        let mut lb = MemoryChipValueCols::default();
        let mut lb_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&mk(Opcode::LB), &mut lb, &mut lb_events);
        let mut lbu = MemoryChipValueCols::default();
        let mut lbu_events = Vec::<ByteLookupEvent>::new();
        chip.event_to_row(&mk(Opcode::LBU), &mut lbu, &mut lbu_events);

        assert_eq!(lbu.mem_limb_low_byte, KoalaBear::from_u8(0xBE));
        assert_eq!(lbu.selected_byte, KoalaBear::from_u8(0xBA));
        assert_eq!(lbu.msb, KoalaBear::ZERO);
        assert_eq!(lbu.lhw_val, KoalaBear::ZERO);
        let u16_count = |ev: &Vec<ByteLookupEvent>| {
            ev.iter()
                .filter(|e| e.opcode == ByteOpcode::U16Range)
                .count()
        };
        assert_eq!(u16_count(&lb_events), u16_count(&lbu_events) + 1);
    }
}
