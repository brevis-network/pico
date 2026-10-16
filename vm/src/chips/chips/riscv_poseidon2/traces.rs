use super::{
    columns::{
        RiscvLastFullRound, RiscvPoseidon2ValueCols, RISCV_NUM_POSEIDON2_COLS,
        RISCV_NUM_POSEIDON2_VALUE_COLS, RISCV_POSEIDON2_NUM_INPUTS, RISCV_POSEIDON2_NUM_OUTPUTS,
    },
    Poseidon2ChipP3,
};
use crate::{
    chips::{
        gadgets::poseidon2::{
            columns::{FullRound, PartialRound},
            constants::RoundConstants,
            traces::{populate_full_round, populate_partial_round, populate_sbox},
        },
        utils::next_power_of_two,
    },
    compiler::riscv::program::Program,
    configs::config::Poseidon2Config,
    emulator::riscv::record::EmulationRecord,
    iter::{join, IndexedPicoIterator, IntoPicoIterator, PicoIterator, PicoSliceMut},
    machine::{chip::ChipBehavior, field::same_field},
    primitives::consts::{PERMUTATION_WIDTH, RISCV_POSEIDON2_DATAPAR},
};
use hybrid_array::Array;
use p3_field::{PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::BorrowMut;
use typenum::Unsigned;

/// Populate one riscv (rate-8) permutation slot: commits `state[0..8]` as `inputs`, requires the
/// capacity lanes `state[8..16]` to be zero (they are constants of the AIR), runs the rounds and
/// checks the output against `expected_output` when given.
pub(crate) fn populate_perm_riscv<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    is_real: F,
    cols: &mut RiscvPoseidon2ValueCols<F, Config>,
    mut state: [F; PERMUTATION_WIDTH],
    expected_output: Option<[F; PERMUTATION_WIDTH]>,
    constants: &RoundConstants<F, Config>,
) {
    cols.is_real = is_real;
    assert!(
        state[RISCV_POSEIDON2_NUM_INPUTS..]
            .iter()
            .all(|lane| *lane == F::ZERO),
        "riscv Poseidon2 event with non-zero capacity input"
    );
    cols.inputs
        .copy_from_slice(&state[..RISCV_POSEIDON2_NUM_INPUTS]);

    populate_perm_rounds_riscv::<F, LinearLayers, Config>(
        &mut state,
        &mut cols.beginning_full_rounds,
        &mut cols.partial_rounds,
        &mut cols.ending_full_rounds,
        &mut cols.last_full_round,
        constants,
    );

    if let Some(expected_output) = expected_output {
        assert_eq!(state, expected_output);
    }
}

/// `populate_perm_rounds` for the riscv layout: the last ending full round records only the
/// `RISCV_POSEIDON2_NUM_OUTPUTS` committed output lanes. `state` holds the full output on return.
pub(crate) fn populate_perm_rounds_riscv<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    beginning_full_rounds: &mut Array<FullRound<F, Config>, Config::HalfFullRounds>,
    partial_rounds: &mut Array<PartialRound<F, Config>, Config::PartialRounds>,
    ending_full_rounds: &mut Array<FullRound<F, Config>, Config::HalfFullRoundsM1>,
    last_full_round: &mut RiscvLastFullRound<F, Config>,
    constants: &RoundConstants<F, Config>,
) {
    LinearLayers::external_linear_layer(state);

    for (full_round, round_constants) in beginning_full_rounds
        .iter_mut()
        .zip(&constants.beginning_full_round_constants)
    {
        populate_full_round::<F, LinearLayers, Config>(state, full_round, round_constants);
    }

    for (partial_round, round_constant) in partial_rounds
        .iter_mut()
        .zip(&constants.partial_round_constants)
    {
        populate_partial_round::<F, LinearLayers, Config>(state, partial_round, *round_constant);
    }

    let last = Config::HalfFullRoundsM1::USIZE;
    for round in 0..last {
        populate_full_round::<F, LinearLayers, Config>(
            state,
            &mut ending_full_rounds[round],
            &constants.ending_full_round_constants[round],
        );
    }

    // The last ending full round: full permutation step, only the output lanes are recorded.
    for (state_i, const_i) in state
        .iter_mut()
        .zip(&constants.ending_full_round_constants[last])
    {
        *state_i += *const_i;
    }
    for (state_i, sbox_i) in state.iter_mut().zip(last_full_round.sbox.iter_mut()) {
        populate_sbox(sbox_i, state_i);
    }
    LinearLayers::external_linear_layer(state);
    last_full_round
        .post
        .copy_from_slice(&state[..RISCV_POSEIDON2_NUM_OUTPUTS]);
}

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > ChipBehavior<F> for Poseidon2ChipP3<F, LinearLayers, Config>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        if same_field::<F, KoalaBear, 4>() {
            "RiscvKoalaBearPoseidon2"
        } else {
            panic!("Unsupported field type");
        }
        .to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let nrows = events.len().div_ceil(RISCV_POSEIDON2_DATAPAR);
        let log_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = next_power_of_two(nrows, log_nrows);

        // Calculate total size once
        let total_cols = RISCV_NUM_POSEIDON2_COLS::<Config>;
        let value_cols = RISCV_NUM_POSEIDON2_VALUE_COLS::<Config>;

        // Initialize values in parallel
        let mut values: Vec<F> = (0..padded_nrows * total_cols)
            .into_pico_iter()
            .map(|_| F::ZERO)
            .collect();

        let populate_len = events.len() * value_cols;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);

        // Create a shared dummy row that can be reused
        let dummy_row = {
            let mut dummy = vec![F::ZERO; value_cols];
            let dummy_cols: &mut RiscvPoseidon2ValueCols<F, Config> =
                dummy.as_mut_slice().borrow_mut();

            populate_perm_riscv::<F, LinearLayers, Config>(
                F::ZERO,
                dummy_cols,
                [F::ZERO; PERMUTATION_WIDTH],
                None,
                &self.constants,
            );
            dummy
        };

        // Process both parts in parallel using join
        join(
            || {
                // Process actual values in parallel
                values_pop
                    .pico_chunks_mut(value_cols)
                    .zip_eq(events)
                    .for_each(|(row, event)| {
                        let cols: &mut RiscvPoseidon2ValueCols<F, Config> = row.borrow_mut();
                        populate_perm_riscv::<F, LinearLayers, Config>(
                            F::ONE,
                            cols,
                            event.input.map(F::from_u32),
                            Some(event.output.map(F::from_u32)),
                            &self.constants,
                        );
                    });
            },
            || {
                // Process dummy values in parallel using the pre-computed dummy row
                values_dummy
                    .pico_chunks_mut(value_cols)
                    .for_each(|row| row.copy_from_slice(&dummy_row));
            },
        );

        RowMajorMatrix::new(values, total_cols)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
