use crate::chips::gadgets::{
    global_accumulation::GlobalAccumulationOperation,
    global_interaction::GlobalInteractionOperation,
};
use pico_derive::AlignedBorrow;

pub const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GlobalCols<T: Copy> {
    pub message: [T; 8],
    pub kind: T,
    pub message_0_16bit_limb: T,
    pub message_0_8bit_limb: T,
    /// The most significant (boolean) bit of message[0] (bit 24) — the 25-bit chunk-clk
    /// budget widening.
    pub message_0_high_bit: T,
    pub interaction: GlobalInteractionOperation<T>,
    pub is_real: T,
    pub is_receive: T,
    pub is_send: T,
    pub accumulation: GlobalAccumulationOperation<T, 1>,
}
