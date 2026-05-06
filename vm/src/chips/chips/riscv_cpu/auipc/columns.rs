use pico_derive::AlignedBorrow;
use std::{marker::PhantomData, mem::size_of};

pub const NUM_AUIPC_COLS: usize = size_of::<AuipcCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AuipcCols<F>(PhantomData<F>);
