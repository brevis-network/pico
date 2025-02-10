use super::Poseidon2ChipP3;
use crate::{
    chips::gadgets::poseidon2::{
        columns::{RiscvPoseidon2Cols, RISCV_NUM_POSEIDON2_COLS},
        constraints::eval_poseidon2,
    },
    configs::config::Poseidon2Config,
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

impl<F, LinearLayers, Config> BaseAir<F> for Poseidon2ChipP3<F, LinearLayers, Config>
where
    F: Sync,
    Config: Poseidon2Config,
{
    fn width(&self) -> usize {
        RISCV_NUM_POSEIDON2_COLS::<Config>
    }
}

impl<F, LinearLayers, CB, Config> Air<CB> for Poseidon2ChipP3<F, LinearLayers, Config>
where
    F: Field,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
    CB: ChipBuilder<F>,
    Config: Poseidon2Config,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &RiscvPoseidon2Cols<CB::Var, Config> = (*local).borrow();

        for local in local.values.iter() {
            let outputs =
                eval_poseidon2::<F, CB, LinearLayers, Config>(builder, local, &self.constants);

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
