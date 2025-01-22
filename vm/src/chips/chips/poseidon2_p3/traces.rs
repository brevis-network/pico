use crate::{
    chips::{
        chips::{
            poseidon2_p3::{
                columns::{
                    FullRound, PartialRound, Poseidon2PreprocessedValueCols, Poseidon2ValueCols,
                    SBox, NUM_POSEIDON2_COLS, NUM_POSEIDON2_VALUE_COLS,
                    NUM_PREPROCESSED_POSEIDON2_COLS, NUM_PREPROCESSED_POSEIDON2_VALUE_COLS,
                },
                constants::RoundConstants,
                Poseidon2ChipP3,
            },
            recursion_memory_v2::MemoryAccessCols,
        },
        utils::next_power_of_two,
    },
    compiler::recursion_v2::{instruction::Instruction::Poseidon2, program::RecursionProgram},
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::ChipBehavior,
    primitives::{
        consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR},
        FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS,
    },
};
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use rayon::{iter::IndexedParallelIterator, join, slice::ParallelSliceMut};
use std::borrow::BorrowMut;

impl<F: PrimeField32, LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>>
    ChipBehavior<F> for Poseidon2ChipP3<F, LinearLayers>
where
    Poseidon2ChipP3<F, LinearLayers>: BaseAir<F>,
{
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2")
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Poseidon2(instr) => Some(instr.as_ref()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nrows = instructions.len().div_ceil(POSEIDON2_DATAPAR);
        let fixed_log2_nrows = program.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_PREPROCESSED_POSEIDON2_COLS];

        let populate_len = instructions.len() * NUM_PREPROCESSED_POSEIDON2_VALUE_COLS;
        values[..populate_len]
            .chunks_mut(NUM_PREPROCESSED_POSEIDON2_VALUE_COLS)
            .zip_eq(instructions)
            .for_each(|(row, instruction)| {
                // Set the memory columns.
                // read once, at the first iteration,
                // write once, at the last iteration.
                *row.borrow_mut() = Poseidon2PreprocessedValueCols {
                    input: instruction.addrs.input,
                    output: std::array::from_fn(|j| MemoryAccessCols {
                        addr: instruction.addrs.output[j],
                        mult: instruction.mults[j],
                    }),
                    is_real_neg: F::NEG_ONE,
                }
            });
        Some(RowMajorMatrix::new(values, NUM_PREPROCESSED_POSEIDON2_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let nrows = events.len().div_ceil(POSEIDON2_DATAPAR);
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_POSEIDON2_COLS];

        let populate_len = events.len() * NUM_POSEIDON2_VALUE_COLS;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop
                    .par_chunks_mut(NUM_POSEIDON2_VALUE_COLS)
                    .zip_eq(events)
                    .for_each(|(row, event)| {
                        let cols: &mut Poseidon2ValueCols<F> = row.borrow_mut();
                        populate_perm::<F, LinearLayers>(
                            F::ONE,
                            cols,
                            event.input,
                            Some(event.output),
                            &self.constants,
                        );
                    });
            },
            || {
                let mut dummy = vec![F::ZERO; NUM_POSEIDON2_VALUE_COLS];
                let dummy = dummy.as_mut_slice();
                let dummy_cols: &mut Poseidon2ValueCols<F> = dummy.borrow_mut();
                populate_perm::<F, LinearLayers>(
                    F::ZERO,
                    dummy_cols,
                    [F::ZERO; PERMUTATION_WIDTH],
                    None,
                    &self.constants,
                );
                values_dummy
                    .par_chunks_mut(NUM_POSEIDON2_VALUE_COLS)
                    .for_each(|row| row.copy_from_slice(&dummy))
            },
        );

        RowMajorMatrix::new(values, NUM_POSEIDON2_COLS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PREPROCESSED_POSEIDON2_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

fn populate_perm<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
>(
    is_real: F,
    perm: &mut Poseidon2ValueCols<F>,
    mut state: [F; PERMUTATION_WIDTH],
    expected_output: Option<[F; PERMUTATION_WIDTH]>,
    constants: &RoundConstants<F>,
) {
    perm.is_real = is_real;

    for (inputs_i, state_i) in perm.inputs.iter_mut().zip(state) {
        *inputs_i += state_i;
    }

    LinearLayers::external_linear_layer(&mut state);

    for (full_round, constants) in perm
        .beginning_full_rounds
        .iter_mut()
        .zip(&constants.beginning_full_round_constants)
    {
        populate_full_round::<F, LinearLayers>(&mut state, full_round, constants);
    }

    for (partial_round, constant) in perm
        .partial_rounds
        .iter_mut()
        .zip(&constants.partial_round_constants)
    {
        populate_partial_round::<F, LinearLayers>(&mut state, partial_round, *constant);
    }

    for (full_round, constants) in perm
        .ending_full_rounds
        .iter_mut()
        .zip(&constants.ending_full_round_constants)
    {
        populate_full_round::<F, LinearLayers>(&mut state, full_round, constants);
    }

    if let Some(expected_output) = expected_output {
        for i in 0..PERMUTATION_WIDTH {
            assert_eq!(state[i], expected_output[i]);
        }
    }
}

#[inline]
fn populate_full_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    full_round: &mut FullRound<F>,
    round_constants: &[F; PERMUTATION_WIDTH],
) {
    for (state_i, const_i) in state.iter_mut().zip(round_constants) {
        *state_i += *const_i;
    }
    for (state_i, sbox_i) in state.iter_mut().zip(full_round.sbox.iter_mut()) {
        populate_sbox(sbox_i, state_i);
    }
    LinearLayers::external_linear_layer(state);

    for (post_i, state_i) in full_round.post.iter_mut().zip(state) {
        *post_i = *state_i;
    }
}

#[inline]
fn populate_partial_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    partial_round: &mut PartialRound<F>,
    round_constant: F,
) {
    state[0] += round_constant;
    populate_sbox(&mut partial_round.sbox, &mut state[0]);
    partial_round.post_sbox = state[0];
    LinearLayers::internal_linear_layer(state);
}

#[inline]
fn populate_sbox<F: PrimeField>(sbox: &mut SBox<F>, x: &mut F) {
    *x = match (FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS) {
        (3, 0) => x.cube(), // case for koalabear
        (5, 1) => {
            // case for m31
            let x2 = x.square();
            let x3 = x2 * *x;
            sbox.0[0] = x3;
            x3 * x2
        }
        (7, 1) => {
            // case for babybear
            let x3 = x.cube();
            sbox.0[0] = x3;
            x3 * x3 * *x
        }
        _ => panic!(
            "Unexpected (SBOX_DEGREE, SBOX_REGISTERS) of ({}, {})",
            FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS
        ),
    }
}
