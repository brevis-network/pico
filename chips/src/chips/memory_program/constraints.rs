use crate::{
    chips::memory_program::{
        columns::{
            MemoryProgramMultCols, MemoryProgramPreprocessedCols, NUM_MEMORY_PROGRAM_MULT_COLS,
        },
        MemoryProgramChip,
    },
    gadgets::is_zero::IsZeroOperation,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use pico_compiler::word::Word;
use pico_emulator::{record::MAX_NUM_PVS, riscv::public_values::PublicValues};
use pico_machine::{
    builder::ChipBuilder,
    lookup::{LookupType, SymbolicLookup},
};
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
        let public_values_slice: [CB::Expr; MAX_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_slice.as_slice().borrow();

        // Constrain `is_first_chunk` to be 1 if and only if the chunk is the first chunk.
        IsZeroOperation::<CB::F>::eval(
            builder,
            // TODO: The chunk should be 1 for the first chunk in public values, need to check.
            // public_values.chunk.clone() - CB::F::one(),
            CB::Expr::zero(),
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

        let mut values = vec![CB::Expr::zero(), CB::Expr::zero(), prep_local.addr.into()];
        values.extend(prep_local.value.map(Into::into));

        builder.looked(SymbolicLookup::new(
            values,
            mult_local.multiplicity.into(),
            LookupType::Memory,
        ));
    }
}
