use super::columns::{MemoryAccessCols, MemoryReadCols, MemoryReadWriteCols, MemoryWriteCols};
use crate::chips::chips::{
    rangecheck::event::RangeRecordBehavior,
    riscv_memory::event::{MemoryReadRecord, MemoryRecord, MemoryRecordEnum, MemoryWriteRecord},
};
use p3_field::Field;

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
