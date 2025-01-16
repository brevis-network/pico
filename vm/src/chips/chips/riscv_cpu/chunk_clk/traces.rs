use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{
        byte::event::ByteRecordBehavior, events::ByteLookupEvent, riscv_cpu::event::CpuEvent,
    },
    compiler::riscv::opcode::ByteOpcode,
};
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populates the chunk, and clk related rows.
    pub(crate) fn populate_chunk_clk(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecordBehavior,
    ) {
        let chunk = event.chunk;
        cols.chunk = F::from_canonical_u32(chunk);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            chunk,
            ByteOpcode::U16Range,
            0,
            0,
            (chunk >> 8) as u8,
            (chunk & u8::MAX as u32) as u8,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            chunk,
            ByteOpcode::U16Range,
            0,
            0,
            (clk_16bit_limb >> 8) as u8,
            (clk_16bit_limb & u8::MAX as u16) as u8,
        ));
        blu_events.add_byte_lookup_event(ByteLookupEvent::new(
            chunk,
            ByteOpcode::U8Range,
            0,
            0,
            clk_8bit_limb,
            0,
        ));
    }
}
