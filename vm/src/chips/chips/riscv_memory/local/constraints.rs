use super::{
    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
    MemoryLocalChip,
};
use crate::machine::{
    builder::ChipBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
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

            let mut values = vec![
                local.initial_chunk.into(),
                local.initial_clk.into(),
                local.addr.into(),
            ];
            values.extend(local.initial_value.map(Into::into));
            // Looked initial values and looking final values for Regional scope.
            builder.looked(SymbolicLookup::new(
                values,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));

            // Send the "receive interaction" to the global table.
            builder.looking(SymbolicLookup::new(
                vec![
                    local.initial_chunk.into(),
                    local.initial_clk.into(),
                    local.addr.into(),
                    local.initial_value[0].into(),
                    local.initial_value[1].into(),
                    local.initial_value[2].into(),
                    local.initial_value[3].into(),
                    CB::Expr::ZERO,
                    CB::Expr::ONE,
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));

            // Send the "send interaction" to the global table.
            builder.looking(SymbolicLookup::new(
                vec![
                    local.final_chunk.into(),
                    local.final_clk.into(),
                    local.addr.into(),
                    local.final_value[0].into(),
                    local.final_value[1].into(),
                    local.final_value[2].into(),
                    local.final_value[3].into(),
                    CB::Expr::ONE,
                    CB::Expr::ZERO,
                    CB::Expr::from_canonical_u8(LookupType::Memory as u8),
                ],
                local.is_real.into(),
                LookupType::Global,
                LookupScope::Regional,
            ));

            let mut values = vec![
                local.final_chunk.into(),
                local.final_clk.into(),
                local.addr.into(),
            ];
            values.extend(local.final_value.map(Into::into));
            builder.looking(SymbolicLookup::new(
                values,
                local.is_real.into(),
                LookupType::Memory,
                LookupScope::Regional,
            ));
        }
    }
}
