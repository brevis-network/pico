use super::Poseidon2ChipP3;
use crate::{
    chips::gadgets::poseidon2::{
        columns::{RiscvPoseidon2Cols, RISCV_NUM_POSEIDON2_COLS},
        constraints::eval_poseidon2,
    },
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;

impl<
        F: Field,
        LinearLayers,
        const FIELD_HALF_FULL_ROUNDS: usize,
        const FIELD_PARTIAL_ROUNDS: usize,
        const FIELD_SBOX_REGISTERS: usize,
    > BaseAir<F>
    for Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >
{
    fn width(&self) -> usize {
        RISCV_NUM_POSEIDON2_COLS::<FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS>
    }
}

impl<
        F: Field,
        LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
        CB: ChipBuilder<F>,
        const FIELD_HALF_FULL_ROUNDS: usize,
        const FIELD_PARTIAL_ROUNDS: usize,
        const FIELD_SBOX_REGISTERS: usize,
    > Air<CB>
    for Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >
where
    Self: BaseAir<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &RiscvPoseidon2Cols<
            CB::Var,
            FIELD_HALF_FULL_ROUNDS,
            FIELD_PARTIAL_ROUNDS,
            FIELD_SBOX_REGISTERS,
        > = (*local).borrow();

        for local in local.values.iter() {
            let outputs = eval_poseidon2::<
                F,
                CB,
                LinearLayers,
                FIELD_HALF_FULL_ROUNDS,
                FIELD_PARTIAL_ROUNDS,
                FIELD_SBOX_REGISTERS,
            >(builder, local, &self.constants);

            let lookup_values = local
                .inputs
                .iter()
                .cloned()
                .map(Into::into)
                .chain(outputs)
                .collect();
            builder.looked(SymbolicLookup::new(
                lookup_values,
                local.is_real.into(),
                LookupType::Poseidon2,
                LookupScope::Regional,
            ));
        }
    }
}
