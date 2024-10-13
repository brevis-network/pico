use crate::chips::chips::byte::NUM_BYTE_LOOKUP_CHANNELS;
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ChannelSelectorCols<T> {
    pub channel_selector: [T; NUM_BYTE_LOOKUP_CHANNELS as usize],
}
