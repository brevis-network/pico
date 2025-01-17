use crate::{
    primitives::consts::SELECT_DATAPAR,
    recursion_v2::types::{Address, SelectIo},
};
use pico_derive::AlignedBorrow;

pub const NUM_SELECT_COLS: usize = size_of::<SelectCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectCols<F: Copy> {
    pub values: [SelectValueCols<F>; SELECT_DATAPAR],
}

pub const NUM_SELECT_VALUE_COLS: usize = size_of::<SelectValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectValueCols<F: Copy> {
    pub vals: SelectIo<F>,
}

pub const NUM_SELECT_PREPROCESSED_COLS: usize = size_of::<SelectPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectPreprocessedCols<F: Copy> {
    pub values: [SelectPreprocessedValueCols<F>; SELECT_DATAPAR],
}

pub const NUM_SELECT_PREPROCESSED_VALUE_COLS: usize = size_of::<SelectPreprocessedValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SelectPreprocessedValueCols<F: Copy> {
    pub is_real: F,
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}
