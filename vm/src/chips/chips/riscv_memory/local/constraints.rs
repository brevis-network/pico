use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::machine::{
    builder::ChipBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for MemoryLocalChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_LOCAL_INIT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryLocalChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryLocalCols<CB::Var> = (*local).borrow();

        for local in local.memory_local_entries.iter() {
            builder.assert_eq(
                local.is_real * local.is_real * local.is_real,
                local.is_real * local.is_real * local.is_real,
            );

            let mut initial_values = vec![
                local.initial_chunk.into(),
                local.initial_clk.into(),
                local.addr.into(),
            ];
            initial_values.extend(local.initial_value.map(Into::into));

            let mut final_values = vec![
                local.final_chunk.into(),
                local.final_clk.into(),
                local.addr.into(),
            ];
            final_values.extend(local.final_value.map(Into::into));

            // Looking initial values and looked final values for Global scope.
            builder.looking(SymbolicLookup::new(
                initial_values.clone(),
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Global,
            ));
            builder.looked(SymbolicLookup::new(
                final_values.clone(),
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Global,
            ));

            // Looked initial values and looking final values for Regional scope.
            builder.looked(SymbolicLookup::new(
                initial_values,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));
            builder.looking(SymbolicLookup::new(
                final_values,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));
        }
    }
}
