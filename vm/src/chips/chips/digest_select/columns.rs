use crate::{compiler::recursion::types::Address, primitives::consts::DIGEST_SELECT_DATAPAR};
use pico_derive::AlignedBorrow;

pub const NUM_DIGEST_SELECT_COLS: usize = core::mem::size_of::<DigestSelectCols<u8>>();
pub const NUM_DIGEST_SELECT_PREPROCESSED_COLS: usize =
    core::mem::size_of::<DigestSelectPreprocessedCols<u8>>();

/// One digest-select operation's preprocessed data.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DigestSelectPreprocessedValueCols<F: Copy> {
    pub is_real: F,
    pub bit_addr: Address<F>,
    pub in1_addrs: [Address<F>; 2],
    pub in2_addrs: [Address<F>; 2],
    pub out_addrs: [Address<F>; 2],
    pub mults: [F; 2],
}

/// Preprocessed columns: DATAPAR independent selects per row.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DigestSelectPreprocessedCols<F: Copy> {
    pub values: [DigestSelectPreprocessedValueCols<F>; DIGEST_SELECT_DATAPAR],
}

/// One digest-select operation's values.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DigestSelectValueCols<F: Copy> {
    pub bit: F,
    pub in1: [F; 8],
    pub in2: [F; 8],
    pub out: [F; 8],
}

/// Main columns: DATAPAR independent selects per row.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DigestSelectCols<F: Copy> {
    pub values: [DigestSelectValueCols<F>; DIGEST_SELECT_DATAPAR],
}
