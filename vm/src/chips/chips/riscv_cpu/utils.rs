use super::{
    columns::{CpuCols, NUM_CPU_COLS},
    opcode_selector::columns::{OpcodeSelectorCols, NUM_OPCODE_SELECTOR_COLS},
};
use p3_util::indices_arr;
use std::mem::transmute;

/// Creates the column map for the CPU.
pub const fn make_col_map() -> CpuCols<usize> {
    let indices_arr = indices_arr::<NUM_CPU_COLS>();
    unsafe { transmute::<[usize; NUM_CPU_COLS], CpuCols<usize>>(indices_arr) }
}

/// Create the column map for the CPU.
pub const fn make_selector_col_map() -> OpcodeSelectorCols<usize> {
    let indices_arr = indices_arr::<NUM_OPCODE_SELECTOR_COLS>();
    unsafe {
        transmute::<[usize; NUM_OPCODE_SELECTOR_COLS], OpcodeSelectorCols<usize>>(indices_arr)
    }
}
