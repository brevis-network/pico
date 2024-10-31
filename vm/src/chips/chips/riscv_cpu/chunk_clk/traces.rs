use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{
        rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
        riscv_cpu::event::CpuEvent,
    },
    compiler::riscv::opcode::RangeCheckOpcode::{U16, U8},
};
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populates the chunk, channel, and clk related rows.
    pub(crate) fn populate_chunk_clk(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        range_events: &mut impl RangeRecordBehavior,
    ) {
        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        cols.channel_selector.populate(event.channel);

        range_events.add_range_lookup_event(RangeLookupEvent::new(U16, event.chunk as u16));
        range_events.add_range_lookup_event(RangeLookupEvent::new(U16, clk_16bit_limb));
        range_events.add_range_lookup_event(RangeLookupEvent::new(U8, clk_8bit_limb.into()));
    }
}
