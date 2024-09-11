use p3_field::Field;
use pico_derive::AlignedBorrow;

// TODO: Replace with the constant in bytes chip.
// use crate::bytes::NUM_BYTE_LOOKUP_CHANNELS;
pub const NUM_BYTE_LOOKUP_CHANNELS: u8 = 16;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ChannelSelectorCols<T> {
    pub channel_selector: [T; NUM_BYTE_LOOKUP_CHANNELS as usize],
}
