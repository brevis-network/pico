use super::{
    columns::{MemoryUnalignedCols, NUM_MEMORY_UNALIGNED_COLS},
    MemoryUnalignedChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    instances::preparer::{gpu_add_host_byte_lookups, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior, riscv_cpu::event::CpuEvent,
            riscv_memory::event::MemoryRecordEnum,
        },
        ffi::FfiOption,
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::{
        emulator::guard::access_width,
        history_view::{has_unaligned, unaligned_steps},
        record::EmulationRecord,
    },
    machine::{chip::ChipBehavior, estimator::EventCapture},
};
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for MemoryUnalignedChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "MemoryUnaligned".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let steps = unaligned_steps(input);
        let rows = match input.shape_chip_size(&self.name()) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(steps.len(), None),
        };
        assert!(
            steps.len() <= rows,
            "{} misaligned loads and stores do not fit the shape's {rows} rows",
            steps.len()
        );
        let mut values = vec![F::ZERO; rows * NUM_MEMORY_UNALIGNED_COLS];
        let code = input.program.code();
        for (row, (event, next)) in values.chunks_mut(NUM_MEMORY_UNALIGNED_COLS).zip(&steps) {
            let cols: &mut MemoryUnalignedCols<F> = row.borrow_mut();
            self.event_to_row(event, *next, &code, cols, &mut ());
        }
        RowMajorMatrix::new(values, NUM_MEMORY_UNALIGNED_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let mut blu = Vec::new();
        let code = input.program.code();
        for (event, next) in unaligned_steps(input) {
            let mut cols = MemoryUnalignedCols::<F>::default();
            self.event_to_row(&event, next, &code, &mut cols, &mut blu);
        }
        extra.add_byte_lookup_events(blu);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // As `MemoryReadWrite`: under a pad shape the shape decides presence.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        has_unaligned(record)
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for MemoryUnalignedChip<F> {
    /// The device side's `is_active`: the same rule, on the counts the host prepared.
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        record.event_counter.num_memory_unaligned > 0
    }

    /// Generated on the host, as the precompiles listed next to it are: its rows are few, at
    /// most `1 << MLE_MEMORY_UNALIGNED_LOG_HEIGHT` a chunk. Its byte lookups go to the device
    /// table, which no kernel of this chip writes.
    fn gpu_generate_extra_record_and_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let mut extra = EmulationRecord::default();
        self.extra_record(input, &mut extra);
        gpu_add_host_byte_lookups(
            std::mem::take(&mut extra.byte_lookups),
            preallocated_gpu_memory,
        )
        .expect("memory unaligned: adding the byte lookups to the device table failed");
        TraceData::Cpu(self.generate_main(input, &mut EmulationRecord::default()))
    }
}

impl<F> EventCapture for MemoryUnalignedChip<F> {}

/// The value a record found before its access.
fn prev_value(record: MemoryRecordEnum) -> u64 {
    match record {
        MemoryRecordEnum::Read(read) => read.value,
        MemoryRecordEnum::Write(write) => write.prev_value,
    }
}

/// A signed load's sign: bit 15 of `src`, and the U16Range event the AIR's check raises.
fn sign<F: Field>(cols: &mut MemoryUnalignedCols<F>, blu: &mut impl ByteRecordBehavior, src: u16) {
    let msb = src >> 15;
    cols.sign_src = F::from_u16(src);
    cols.msb = F::from_u16(msb);
    blu.add_u16_range_check((u32::from(src) * 2 - u32::from(msb) * (1 << 16)) as u16);
}

impl<F: Field> MemoryUnalignedChip<F> {
    /// The row of one load or store. `next` is the access to the dword after the one holding the
    /// first byte, which an access that crosses into it has and no other does; `code` is the
    /// program's code, which a store must miss.
    pub(crate) fn event_to_row(
        &self,
        event: &CpuEvent,
        next: Option<MemoryRecordEnum>,
        code: &core::ops::Range<u64>,
        cols: &mut MemoryUnalignedCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let opcode = event.instruction.opcode;
        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(
            u32::try_from(event.clk)
                .unwrap_or_else(|_| panic!("clk 0x{:x} does not fit a u32", event.clk)),
        );
        cols.instruction.populate(event);

        // The address, its limbs, and the dword it starts in.
        let addr = event.b.wrapping_add(event.c);
        assert!(
            addr < 1 << 32,
            "memory address must be less than 2^32, not 0x{addr:x}"
        );
        let limb0 = addr as u16;
        let limb1 = (addr >> 16) as u16;
        cols.addr_word = [F::from_u16(limb0), F::from_u16(limb1)];
        blu.add_u16_range_check(limb1);
        // Below 2^16 the inverse does not exist: zero leaves the row unsatisfiable rather than
        // panicking here, as `MemoryReadWrite` and `SyscallAddrGadget` do.
        cols.addr_limb1_inv = F::from_u16(limb1).try_inverse().unwrap_or(F::ZERO);
        let offset = (addr % 8) as usize;
        cols.offset[offset] = F::ONE;
        let dword0 = limb0 - offset as u16;
        blu.add_bit_range_check(dword0 / 8, 13);

        let crosses = offset as u64 + access_width(opcode) > 8;
        cols.cross = F::from_bool(crosses);
        let carry = dword0 == 0xfff8;
        cols.next_carry = F::from_bool(carry);
        cols.next_carry_inv = if carry {
            F::ZERO
        } else {
            (F::from_u16(dword0) - F::from_u16(0xfff8)).inverse()
        };

        // The two dwords before the access.
        let FfiOption::Some(record) = event.memory_record else {
            panic!("{opcode:?} at 0x{addr:x} has no memory record");
        };
        cols.first.populate(record, blu);
        let first = prev_value(record);
        cols.first_bytes.populate_u16_to_u8_safe(blu, first);
        let second = match (crosses, next) {
            (true, Some(next)) => {
                let next1 = limb1
                    .checked_add(u16::from(carry))
                    .unwrap_or_else(|| panic!("{opcode:?} at 0x{addr:x} runs past 2^32"));
                blu.add_u16_range_check(next1);
                cols.second.populate(next, blu);
                let second = prev_value(next);
                cols.second_bytes.populate_u16_to_u8_safe(blu, second);
                second
            }
            (false, None) => 0,
            (true, None) => {
                panic!("{opcode:?} at 0x{addr:x} runs into the next dword, whose access is missing")
            }
            (false, Some(_)) => {
                panic!("{opcode:?} at 0x{addr:x} stays in its dword, but has a second access")
            }
        };

        // What a load reads, before its fill.
        let seen = ((u128::from(first) | (u128::from(second) << 64)) >> (8 * offset)) as u64;
        cols.seen = Word::from(seen);
        cols.seen_byte = F::from_u8(seen as u8);

        match opcode {
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                let value = match event.a_record {
                    FfiOption::Some(record) => record.value(),
                    FfiOption::None => event.a,
                };
                cols.value_bytes.populate_u16_to_u8_safe(blu, value);
                cols.code_range
                    .populate(addr, access_width(opcode), code, blu);
            }
            Opcode::LB => sign(cols, blu, 256 * u16::from(seen as u8)),
            Opcode::LH => sign(cols, blu, seen as u16),
            Opcode::LW => sign(cols, blu, (seen >> 16) as u16),
            Opcode::LBU | Opcode::LHU | Opcode::LWU | Opcode::LD => {}
            _ => panic!("{opcode:?} is not a load or store"),
        }
    }
}
