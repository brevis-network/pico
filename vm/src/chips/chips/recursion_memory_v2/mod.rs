pub mod constant;
pub mod variable;

use crate::recursion_v2::{
    air::Block,
    types::{Address, MemIo},
};
use pico_derive::AlignedBorrow;

pub const NUM_MEM_ACCESS_COLS: usize = core::mem::size_of::<MemoryAccessCols<u8>>();

/// Data describing in what manner to access a particular memory block.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryAccessCols<F: Copy> {
    /// The address to access.
    pub addr: Address<F>,
    /// The multiplicity which to read/write.
    /// "Positive" values indicate a write, and "negative" values indicate a read.
    pub mult: F,
}

pub type MemEvent<F> = MemIo<Block<F>>;

#[cfg(test)]
mod tests {
    use super::{constant::MemoryConstChip, variable::MemoryVarChip, MemEvent};
    use crate::{
        compiler::recursion_v2::{instruction::mem, program::RecursionProgram},
        machine::chip::ChipBehavior,
        recursion_v2::{runtime::RecursionRecord, types::MemAccessKind},
    };
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use p3_matrix::dense::RowMajorMatrix;

    #[test]
    pub fn recursion_mem_chip_generate_main() {
        let chunk = RecursionRecord::<BabyBear> {
            mem_var_events: vec![
                MemEvent {
                    inner: BabyBear::ONE.into(),
                },
                MemEvent {
                    inner: BabyBear::ONE.into(),
                },
            ],
            ..Default::default()
        };
        let const_chip = MemoryConstChip::default();
        let const_trace: RowMajorMatrix<BabyBear> =
            const_chip.generate_main(&chunk, &mut RecursionRecord::default());

        println!("Memory constant chip: trace = {:?}", const_trace.values);

        let var_chip = MemoryVarChip::default();
        let var_trace: RowMajorMatrix<BabyBear> =
            var_chip.generate_main(&chunk, &mut RecursionRecord::default());
        println!("Memory variable chip: trace = {:?}", var_trace.values);
    }

    /*
    #[test]
    pub fn recursion_mem_chip_prove() {
        let program = RecursionProgram {
            instructions: vec![
                mem(MemAccessKind::Write, 1, 1, 2),
                mem(MemAccessKind::Read, 1, 1, 2),
            ],
            ..Default::default()
        };

        run_recursion_test_machine(program);
    }

    #[test]
    #[should_panic]
    pub fn recursion_mem_chip_bad_multi() {
        let program = RecursionProgram {
            instructions: vec![
                mem(MemAccessKind::Write, 1, 1, 2),
                mem(MemAccessKind::Read, 999, 1, 2),
            ],
            ..Default::default()
        };

        run_recursion_test_machine(program);
    }

    #[test]
    #[should_panic]
    pub fn recursion_mem_chip_bad_address() {
        let program = RecursionProgram {
            instructions: vec![
                mem(MemAccessKind::Write, 1, 1, 2),
                mem(MemAccessKind::Read, 1, 999, 2),
            ],
            ..Default::default()
        };

        run_recursion_test_machine(program);
    }

    #[test]
    #[should_panic]
    pub fn recursion_mem_chip_bad_value() {
        let program = RecursionProgram {
            instructions: vec![
                mem(MemAccessKind::Write, 1, 1, 2),
                mem(MemAccessKind::Read, 1, 1, 999),
            ],
            ..Default::default()
        };

        run_recursion_test_machine(program);
    }
    */
}
