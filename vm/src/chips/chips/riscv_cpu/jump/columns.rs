use pico_derive::AlignedBorrow;
use std::{marker::PhantomData, mem::size_of};

pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct JumpCols<F>(PhantomData<F>);
