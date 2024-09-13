use crate::chips::cpu::{columns::CpuCols, CpuChip};
use p3_field::Field;
use pico_emulator::events::{ByteRecord, CpuEvent};

impl<F: Field> CpuChip<F> {
    /// Populates the shard, channel, and clk related rows.
    pub(crate) fn populate_shard_clk(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecord,
    ) {
        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.clk = F::from_canonical_u32(event.clk);

        let clk_16bit_limb = (event.clk & 0xffff) as u16;
        let clk_8bit_limb = ((event.clk >> 16) & 0xff) as u8;
        cols.clk_16bit_limb = F::from_canonical_u16(clk_16bit_limb);
        cols.clk_8bit_limb = F::from_canonical_u8(clk_8bit_limb);

        cols.channel_selector.populate(event.channel);

        /* TODO: Enable after adding the byte chip.
                blu_events.add_byte_lookup_event(ByteLookupEvent::new(
                    event.shard,
                    event.channel,
                    U16Range,
                    event.shard as u16,
                    0,
                    0,
                    0,
                ));
                blu_events.add_byte_lookup_event(ByteLookupEvent::new(
                    event.shard,
                    event.channel,
                    U16Range,
                    clk_16bit_limb,
                    0,
                    0,
                    0,
                ));
                blu_events.add_byte_lookup_event(ByteLookupEvent::new(
                    event.shard,
                    event.channel,
                    ByteOpcode::U8Range,
                    0,
                    0,
                    0,
                    clk_8bit_limb as u8,
                ));
        */
    }
}
