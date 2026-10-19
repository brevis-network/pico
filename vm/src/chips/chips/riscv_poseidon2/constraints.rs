use super::{
    columns::{
        RiscvLastFullRound, RiscvPoseidon2Cols, RISCV_NUM_POSEIDON2_COLS,
        RISCV_POSEIDON2_NUM_INPUTS, RISCV_POSEIDON2_NUM_OUTPUTS,
    },
    Poseidon2ChipP3,
};
use crate::{
    chips::gadgets::poseidon2::{
        columns::{FullRound, PartialRound},
        constants::RoundConstants,
        constraints::{eval_full_round, eval_partial_round, eval_sbox},
    },
    configs::config::Poseidon2Config,
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::PERMUTATION_WIDTH,
};
use hybrid_array::Array;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;
use typenum::Unsigned;

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
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    CB: ChipBuilder<F>,
    Config: Poseidon2Config,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &RiscvPoseidon2Cols<CB::Var, Config> = (*local).borrow();

        for local in local.values.iter() {
            // The Global chip (the only producer of this lookup) always feeds a rate-8 input with
            // zero capacity, so the capacity lanes are not committed: they enter the permutation
            // as the constant zero, which pins the full input from the bound prefix and keeps the
            // truncated `(inputs[0..8], outputs[0..7])` lookup tuple (15-wide) binding sound.
            let state: [CB::Expr; PERMUTATION_WIDTH] = core::array::from_fn(|i| {
                if i < RISCV_POSEIDON2_NUM_INPUTS {
                    local.inputs[i].into()
                } else {
                    CB::Expr::ZERO
                }
            });
            let outputs = eval_poseidon2_rounds_riscv::<F, CB, LinearLayers, Config>(
                builder,
                state,
                &local.beginning_full_rounds,
                &local.partial_rounds,
                &local.ending_full_rounds,
                &local.last_full_round,
                &self.constants,
            );

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

/// The permutation rounds of the riscv layout: `eval_poseidon2_rounds` with the last ending full
/// round asserting (and returning) only the `RISCV_POSEIDON2_NUM_OUTPUTS` lanes the lookup reads.
/// The other lanes of that round are not committed: in the full-width system each of them appears
/// in no constraint but its own definition `post_i = M_E(S(state + rc))_i`, so dropping them is a
/// projection of that system (any accepted witness extends uniquely to the full-width one).
fn eval_poseidon2_rounds_riscv<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    builder: &mut CB,
    mut state: [CB::Expr; PERMUTATION_WIDTH],
    beginning_full_rounds: &Array<FullRound<CB::Var, Config>, Config::HalfFullRounds>,
    partial_rounds: &Array<PartialRound<CB::Var, Config>, Config::PartialRounds>,
    ending_full_rounds: &Array<FullRound<CB::Var, Config>, Config::HalfFullRoundsM1>,
    last_full_round: &RiscvLastFullRound<CB::Var, Config>,
    round_constants: &RoundConstants<F, Config>,
) -> [CB::Expr; RISCV_POSEIDON2_NUM_OUTPUTS] {
    LinearLayers::external_linear_layer(&mut state);

    for round in 0..Config::HalfFullRounds::USIZE {
        eval_full_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &beginning_full_rounds[round],
            &round_constants.beginning_full_round_constants[round],
            builder,
        );
    }

    for round in 0..Config::PartialRounds::USIZE {
        eval_partial_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &partial_rounds[round],
            &round_constants.partial_round_constants[round],
            builder,
        );
    }

    let last = Config::HalfFullRoundsM1::USIZE;
    for round in 0..last {
        eval_full_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &ending_full_rounds[round],
            &round_constants.ending_full_round_constants[round],
            builder,
        );
    }

    // The last ending full round, committed only on the output lanes.
    let constants = &round_constants.ending_full_round_constants[last];
    for (i, (s, r)) in state.iter_mut().zip(constants.iter()).enumerate() {
        *s = s.clone() + *r;
        eval_sbox::<F, CB, Config>(&last_full_round.sbox[i], s, builder);
    }
    LinearLayers::external_linear_layer(&mut state);
    core::array::from_fn(|i| {
        builder.assert_eq(state[i].clone(), last_full_round.post[i]);
        last_full_round.post[i].into()
    })
}
