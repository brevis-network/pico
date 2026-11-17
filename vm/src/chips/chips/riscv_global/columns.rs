use pico_derive::AlignedBorrow;
use pico_mle_core::global_logup::{MULTIPLICITY_COL, TABLE_WIDTH};

pub const NUM_GLOBAL_COLS: usize = size_of::<GlobalCols<u8>>();
/// The leading columns of a row are the chunk's cross-chunk event table, in the layout the
/// global-LogUp group proofs read (`pico_mle_core::global_logup`). The MLE machine commits them
/// on their own, as the Global AIR's cached main trace.
pub const NUM_GLOBAL_TABLE_COLS: usize = TABLE_WIDTH;
/// The remaining columns, which only this chunk's proof reads: the AIR's common main trace.
pub const NUM_GLOBAL_AUX_COLS: usize = NUM_GLOBAL_COLS - NUM_GLOBAL_TABLE_COLS;

/// One cross-chunk event per row; padding rows are all zero.
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GlobalCols<T: Copy> {
    // The event table.
    pub message: [T; 8],
    pub kind: T,
    /// The row's multiplicity in the global LogUp: `+1` for a send, `-1` for a receive, `0` on a
    /// padding row.
    pub mu: T,

    // The rest.
    pub is_real: T,
    pub is_send: T,
    pub is_receive: T,
    pub message_0_16bit_limb: T,
    pub message_0_8bit_limb: T,
    /// The most significant (boolean) bit of message[0] (bit 24) — the 25-bit chunk-clk
    /// budget widening.
    pub message_0_high_bit: T,
    /// 16 + 9 limb decomposition of message[1], range-checking it to 25 bits: the clk
    /// of a memory message, which otherwise only the bus cancellation binds.
    pub message_1_16bit_limb: T,
    pub message_1_hi9: T,
}

const _: () = {
    assert!(std::mem::offset_of!(GlobalCols<u8>, message) == 0);
    assert!(std::mem::offset_of!(GlobalCols<u8>, kind) == 8);
    assert!(std::mem::offset_of!(GlobalCols<u8>, mu) == MULTIPLICITY_COL);
    assert!(std::mem::offset_of!(GlobalCols<u8>, is_real) == NUM_GLOBAL_TABLE_COLS);
};
