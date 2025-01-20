use super::{
    columns::{
        NumPoseidon2ColsGeneric, Poseidon2Cols, Poseidon2PreprocessedCols,
        NUM_POSEIDON2_PREPROCESSED_COLS,
    },
    Poseidon2SkinnyChip,
};
use crate::{
    chips::chips::{
        poseidon2::utils::{external_linear_layer, internal_linear_layer},
        recursion_memory_v2::MemoryAccessCols,
    },
    compiler::recursion_v2::{instruction::Instruction, program::RecursionProgram},
    configs::config::Poseidon2Config,
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::ChipBehavior,
        utils::{pad_to_power_of_two, pad_to_power_of_two_noconst},
    },
    primitives::{consts::PERMUTATION_WIDTH, RC_16_30_U32},
};
use hybrid_array::Array;
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::{
    array,
    borrow::{Borrow, BorrowMut},
};
use typenum::Sum;

impl<const DEGREE: usize, Config: Poseidon2Config, F: PrimeField32> ChipBehavior<F>
    for Poseidon2SkinnyChip<DEGREE, Config, F>
where
    Poseidon2SkinnyChip<DEGREE, Config, F>: BaseAir<F>,
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2SkinnyDeg{}", DEGREE)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_POSEIDON2_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions =
            program
                .instructions
                .iter()
                .filter_map(|instruction| match instruction {
                    Instruction::Poseidon2(instr) => Some(instr),
                    _ => None,
                });

        let num_instructions = instructions.clone().count();

        let mut rows = vec![
            [F::ZERO; NUM_POSEIDON2_PREPROCESSED_COLS];
            num_instructions * (Self::NUM_EXTERNAL_ROUNDS + 3)
        ];

        // Iterate over the instructions and take NUM_EXTERNAL_ROUNDS + 3 rows for each instruction.
        // We have one extra round for the internal rounds, one extra round for the input,
        // and one extra round for the output.
        instructions
            .zip_eq(&rows.iter_mut().chunks(Self::NUM_EXTERNAL_ROUNDS + 3))
            .for_each(|(instruction, row_add)| {
                row_add.into_iter().enumerate().for_each(|(i, row)| {
                    let cols: &mut Poseidon2PreprocessedCols<_> =
                        (*row).as_mut_slice().borrow_mut();

                    // Set the round-counter columns.
                    cols.round_counters_preprocessed.is_input_round = F::from_bool(i == 0);
                    let is_external_round =
                        i != 0 && i != Self::INTERNAL_ROUND_IDX && i != Self::OUTPUT_ROUND_IDX;
                    cols.round_counters_preprocessed.is_external_round =
                        F::from_bool(is_external_round);
                    cols.round_counters_preprocessed.is_internal_round =
                        F::from_bool(i == Self::INTERNAL_ROUND_IDX);

                    (0..PERMUTATION_WIDTH).for_each(|j| {
                        cols.round_counters_preprocessed.round_constants[j] = if is_external_round {
                            let r = i - 1;
                            let round = if i < Self::INTERNAL_ROUND_IDX {
                                r
                            } else {
                                r + Self::NUM_INTERNAL_ROUNDS - 1
                            };

                            F::from_wrapped_u32(RC_16_30_U32[round][j])
                        } else if i == Self::INTERNAL_ROUND_IDX {
                            F::from_wrapped_u32(RC_16_30_U32[Self::NUM_EXTERNAL_ROUNDS / 2 + j][0])
                        } else {
                            F::ZERO
                        };
                    });

                    // Set the memory columns. We read once, at the first iteration,
                    // and write once, at the last iteration.
                    if i == 0 {
                        cols.memory_preprocessed =
                            instruction.addrs.input.map(|addr| MemoryAccessCols {
                                addr,
                                mult: F::NEG_ONE,
                            });
                    } else if i == Self::OUTPUT_ROUND_IDX {
                        cols.memory_preprocessed = array::from_fn(|i| MemoryAccessCols {
                            addr: instruction.addrs.output[i],
                            mult: instruction.mults[i],
                        });
                    }
                });
            });

        let trace_rows = rows.into_iter().flatten().collect_vec();
        let mut trace = RowMajorMatrix::new(trace_rows, NUM_POSEIDON2_PREPROCESSED_COLS);

        // Pad the trace to a power of two based on shape, if available.
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_POSEIDON2_PREPROCESSED_COLS, F>(&mut trace.values, log_size);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for event in &input.poseidon2_events {
            // We have one row for input, one row for output, NUM_EXTERNAL_ROUNDS rows for the
            // external rounds, and one row for all internal rounds.
            //let mut row_add = [[F::ZERO; $num_poseidon2_col]; $num_external_rounds + 3];
            let mut row_add: Array<
                Array<F, NumPoseidon2ColsGeneric<Config>>,
                Sum<Config::ExternalRounds, typenum::U3>,
            > = Default::default();

            // The first row should have event.input and [event.input[0].clone();
            // NUM_INTERNAL_ROUNDS-1] in its state columns. The sbox_state will be
            // modified in the computation of the first row.
            {
                let (first_row, second_row) = &mut row_add[0..2].split_at_mut(1);
                let input_cols: &mut Poseidon2Cols<F, Config> =
                    first_row[0].as_mut_slice().borrow_mut();
                input_cols.state_var = event.input;

                let next_cols: &mut Poseidon2Cols<F, Config> =
                    second_row[0].as_mut_slice().borrow_mut();
                next_cols.state_var = event.input;
                external_linear_layer(&mut next_cols.state_var);
            }

            // For each external round, and once for all the internal rounds at the same time, apply
            // the corresponding operation. This will change the state and internal_rounds_s0
            // variable in row r+1.
            for i in 1..Self::OUTPUT_ROUND_IDX {
                let next_state_var = {
                    let cols: &mut Poseidon2Cols<F, Config> =
                        row_add[i].as_mut_slice().borrow_mut();
                    let state = cols.state_var;

                    if i != Self::INTERNAL_ROUND_IDX {
                        self.populate_external_round(&state, i - 1)
                    } else {
                        // Populate the internal rounds.
                        self.populate_internal_rounds(&state, &mut cols.internal_rounds_s0)
                    }
                };
                let next_row_cols: &mut Poseidon2Cols<F, Config> =
                    row_add[i + 1].as_mut_slice().borrow_mut();
                next_row_cols.state_var = next_state_var;
            }

            // Check that the permutation is computed correctly.
            {
                let last_row_cols: &Poseidon2Cols<F, Config> =
                    row_add[Self::OUTPUT_ROUND_IDX].as_slice().borrow();
                debug_assert_eq!(last_row_cols.state_var, event.output);
            }
            rows.extend(row_add.into_iter());
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            Self::NUM_POSEIDON2_COLS,
        );

        // Pad the trace to a power of two based on shape, if available.
        let log_size = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two_noconst(Self::NUM_POSEIDON2_COLS, &mut trace.values, log_size);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<const DEGREE: usize, Config: Poseidon2Config, F: PrimeField32>
    Poseidon2SkinnyChip<DEGREE, Config, F>
{
    fn populate_external_round(
        &self,
        round_state: &[F; PERMUTATION_WIDTH],
        r: usize,
    ) -> [F; PERMUTATION_WIDTH] {
        let mut state = {
            // Add round constants.

            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, and instead include it in the constraint for the x^3 part of the
            // sbox.
            let round = if r < Self::NUM_EXTERNAL_ROUNDS / 2 {
                r
            } else {
                r + Self::NUM_INTERNAL_ROUNDS - 1
            };
            let mut add_rc = *round_state;
            (0..PERMUTATION_WIDTH)
                .for_each(|i| add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]));

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, and instead include the x^3 -> x^7
            // part of the sbox in the constraint for the linear layer
            let mut sbox_deg_7: [F; 16] = [F::ZERO; PERMUTATION_WIDTH];
            for i in 0..PERMUTATION_WIDTH {
                let sbox_deg_3 = add_rc[i] * add_rc[i] * add_rc[i];
                sbox_deg_7[i] = sbox_deg_3 * sbox_deg_3 * add_rc[i];
            }

            sbox_deg_7
        };
        // Apply the linear layer.
        external_linear_layer(&mut state);
        state
    }

    fn populate_internal_rounds(
        &self,
        state: &[F; PERMUTATION_WIDTH],
        internal_rounds_s0: &mut Array<F, Config::InternalRoundsM1>,
    ) -> [F; PERMUTATION_WIDTH] {
        let mut new_state = *state;
        (0..Self::NUM_INTERNAL_ROUNDS).for_each(|r| {
            // Add the round constant to the 0th state element.
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, just like for external rounds.
            let round = r + Self::NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = new_state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // Apply the sboxes.
            // Optimization: since the linear layer that comes after the sbox is degree 1, we can
            // avoid adding columns for the result of the sbox, just like for external rounds.
            let sbox_deg_3 = add_rc * add_rc * add_rc;
            let sbox_deg_7 = sbox_deg_3 * sbox_deg_3 * add_rc;

            // Apply the linear layer.
            new_state[0] = sbox_deg_7;
            internal_linear_layer::<F, _>(&mut new_state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < Self::NUM_INTERNAL_ROUNDS - 1 {
                internal_rounds_s0[r] = new_state[0];
            }
        });

        new_state
    }
}

//implement_poseidon2_skinny_chip!(
//    BABYBEAR_NUM_EXTERNAL_ROUNDS,
//    BABYBEAR_NUM_INTERNAL_ROUNDS,
//    BABYBEAR_NUM_POSEIDON2_COLS,
//    (BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 + 1),
//    0,
//    BABYBEAR_NUM_EXTERNAL_ROUNDS + 2
//);
//implement_poseidon2_skinny_chip!(
//    KOALABEAR_NUM_EXTERNAL_ROUNDS,
//    KOALABEAR_NUM_INTERNAL_ROUNDS,
//    KOALABEAR_NUM_POSEIDON2_COLS,
//    (KOALABEAR_NUM_EXTERNAL_ROUNDS / 2 + 1),
//    0,
//    KOALABEAR_NUM_EXTERNAL_ROUNDS + 2
//);
