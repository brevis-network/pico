use crate::chips::gadgets::{
    global_accumulation::GlobalAccumulationOperation,
    global_interaction::GlobalInteractionOperation,
};
use pico_derive::AlignedBorrow;

pub const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GlobalCols<T: Copy> {
    pub message: [T; 7],
    pub kind: T,
    pub interaction: GlobalInteractionOperation<T>,
    pub is_receive: T,
    pub is_send: T,
    pub is_real: T,
    pub accumulation: GlobalAccumulationOperation<T, 1>,
}
