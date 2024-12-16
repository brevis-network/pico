use crate::{
    chips::{
        chips::memory_program::{
            columns::{
                MemoryProgramMultCols, MemoryProgramPreprocessedCols, NUM_MEMORY_PROGRAM_MULT_COLS,
            },
            MemoryProgramChip,
        },
        gadgets::is_zero::IsZeroGadget,
    },
    compiler::word::Word,
    emulator::riscv::public_values::PublicValues,
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::RISCV_NUM_PVS,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::{array, borrow::Borrow};

impl<F: Field> BaseAir<F> for MemoryProgramChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_PROGRAM_MULT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryProgramChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let preprocessed = builder.preprocessed();
        let main = builder.main();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &MemoryProgramPreprocessedCols<CB::Var> = (*prep_local).borrow();

        let mult_local = main.row_slice(0);
        let mult_local: &MemoryProgramMultCols<CB::Var> = (*mult_local).borrow();

        // Get chunk from public values and evaluate whether it is the first chunk.
        let public_values_slice: [CB::Expr; RISCV_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_slice.as_slice().borrow();

        // Constrain `is_first_chunk` to be 1 if and only if the chunk is the first chunk.
        IsZeroGadget::<CB::F>::eval(
            builder,
            public_values.chunk.clone() - CB::F::ONE,
            mult_local.is_first_chunk,
            prep_local.is_real.into(),
        );

        // Multiplicity must be either 0 or 1.
        builder.assert_bool(mult_local.multiplicity);

        // If first chunk and preprocessed is real, multiplicity must be one.
        builder
            .when(mult_local.is_first_chunk.result)
            .assert_eq(mult_local.multiplicity, prep_local.is_real.into());

        // If it's not the first chunk, then the multiplicity must be zero.
        builder
            .when_not(mult_local.is_first_chunk.result)
            .assert_zero(mult_local.multiplicity);

        let mut values = vec![CB::Expr::ZERO, CB::Expr::ZERO, prep_local.addr.into()];
        values.extend(prep_local.value.map(Into::into));

        builder.looked(SymbolicLookup::new(
            values,
            mult_local.multiplicity.into(),
            LookupType::Memory,
            LookupScope::Global,
        ));
    }
}
