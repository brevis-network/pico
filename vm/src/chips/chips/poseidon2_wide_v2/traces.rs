use std::borrow::BorrowMut;

use crate::{
    chips::{
        chips::{
            poseidon2_wide_v2::{
                columns::preprocessed::{Poseidon2PreprocessedCols, PREPROCESSED_POSEIDON2_WIDTH},
                Poseidon2WideChip,
            },
            recursion_memory_v2::MemoryAccessCols,
        },
        poseidon2::{external_linear_layer, external_linear_layer_immut, internal_linear_layer},
    },
    compiler::recursion_v2::{instruction::Instruction::Poseidon2, program::RecursionProgram},
    machine::{
        chip::ChipBehavior,
        field::{FieldBehavior, FieldType},
    },
    primitives::{consts::PERMUTATION_WIDTH, RC_16_30_U32},
    recursion_v2::{runtime::RecursionRecord, stark::utils::next_power_of_two},
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use super::columns::permutation::{babybear_permutation_mut, koalabear_permutation_mut};

impl<
        F: PrimeField32,
        const DEGREE: usize,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    > ChipBehavior<F>
    for Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >
where
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >: BaseAir<F>,
{
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        format!("Poseidon2WideDeg{}", DEGREE)
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

        let padded_nb_rows = match program.fixed_log2_rows(&self.name()) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(instructions.len(), None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * PREPROCESSED_POSEIDON2_WIDTH];

        let populate_len = instructions.len() * PREPROCESSED_POSEIDON2_WIDTH;
        values[..populate_len]
            .par_chunks_mut(PREPROCESSED_POSEIDON2_WIDTH)
            .zip_eq(instructions)
            .for_each(|(row, instruction)| {
                // Set the memory columns.
                // read once, at the first iteration,
                // write once, at the last iteration.
                *row.borrow_mut() = Poseidon2PreprocessedCols {
                    input: instruction.addrs.input,
                    output: std::array::from_fn(|j| MemoryAccessCols {
                        addr: instruction.addrs.output[j],
                        mult: instruction.mults[j],
                    }),
                    is_real_neg: F::NEG_ONE,
                }
            });
        Some(RowMajorMatrix::new(values, PREPROCESSED_POSEIDON2_WIDTH))
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _output: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_events;
        let padded_nb_rows = match input.fixed_log2_rows(&self.name()) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(events.len(), None),
        };
        let num_columns = <Self as BaseAir<F>>::width(self);
        let mut values = vec![F::ZERO; padded_nb_rows * num_columns];

        let populate_len = events.len() * num_columns;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop
                    .par_chunks_mut(num_columns)
                    .zip_eq(&input.poseidon2_events)
                    .for_each(|(row, &event)| {
                        self.populate_perm(event.input, Some(event.output), row);
                    })
            },
            || {
                let mut dummy_row = vec![F::ZERO; num_columns];
                self.populate_perm([F::ZERO; PERMUTATION_WIDTH], None, &mut dummy_row);
                values_dummy
                    .par_chunks_mut(num_columns)
                    .for_each(|row| row.copy_from_slice(&dummy_row))
            },
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, num_columns)
    }

    fn preprocessed_width(&self) -> usize {
        PREPROCESSED_POSEIDON2_WIDTH
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<
        F: PrimeField32,
        const DEGREE: usize,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    >
    Poseidon2WideChip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >
{
    fn populate_perm(
        &self,
        input: [F; PERMUTATION_WIDTH],
        expected_output: Option<[F; PERMUTATION_WIDTH]>,
        input_row: &mut [F],
    ) {
        match F::field_type() {
            FieldType::TypeBabyBear => {
                self.populate_perm_babybear(input, expected_output, input_row)
            }
            FieldType::TypeKoalaBear => {
                self.populate_perm_koalabear(input, expected_output, input_row)
            }
            _ => panic!("Unsupported field type"),
        }
    }

    fn populate_perm_babybear(
        &self,
        input: [F; PERMUTATION_WIDTH],
        expected_output: Option<[F; PERMUTATION_WIDTH]>,
        input_row: &mut [F],
    ) {
        assert_eq!(F::field_type(), FieldType::TypeBabyBear);
        let permutation = babybear_permutation_mut::<
            F,
            DEGREE,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >(input_row);

        let (
            external_rounds_state,
            internal_rounds_state,
            internal_rounds_s0,
            mut external_sbox,
            mut internal_sbox,
            output_state,
        ) = permutation.get_cols_mut();

        external_rounds_state[0] = input;

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            let next_state =
                self.populate_external_round(external_rounds_state, &mut external_sbox, r);
            if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                *internal_rounds_state = next_state;
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }

        // Apply the internal rounds.
        external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] = self.populate_internal_rounds(
            internal_rounds_state,
            internal_rounds_s0,
            &mut internal_sbox,
        );

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            let next_state =
                self.populate_external_round(external_rounds_state, &mut external_sbox, r);
            if r == NUM_EXTERNAL_ROUNDS - 1 {
                for i in 0..PERMUTATION_WIDTH {
                    output_state[i] = next_state[i];
                    if let Some(expected_output) = expected_output {
                        assert_eq!(expected_output[i], next_state[i]);
                    }
                }
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }
    }

    fn populate_perm_koalabear(
        &self,
        input: [F; PERMUTATION_WIDTH],
        expected_output: Option<[F; PERMUTATION_WIDTH]>,
        input_row: &mut [F],
    ) {
        assert_eq!(F::field_type(), FieldType::TypeKoalaBear);
        let permutation = koalabear_permutation_mut::<
            F,
            DEGREE,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >(input_row);

        let (
            external_rounds_state,
            internal_rounds_state,
            internal_rounds_s0,
            mut external_sbox,
            mut internal_sbox,
            output_state,
        ) = permutation.get_cols_mut();

        external_rounds_state[0] = input;

        // Apply the first half of external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS / 2 {
            let next_state =
                self.populate_external_round(external_rounds_state, &mut external_sbox, r);
            if r == NUM_EXTERNAL_ROUNDS / 2 - 1 {
                *internal_rounds_state = next_state;
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }

        // Apply the internal rounds.
        external_rounds_state[NUM_EXTERNAL_ROUNDS / 2] = self.populate_internal_rounds(
            internal_rounds_state,
            internal_rounds_s0,
            &mut internal_sbox,
        );

        // Apply the second half of external rounds.
        for r in NUM_EXTERNAL_ROUNDS / 2..NUM_EXTERNAL_ROUNDS {
            let next_state =
                self.populate_external_round(external_rounds_state, &mut external_sbox, r);
            if r == NUM_EXTERNAL_ROUNDS - 1 {
                for i in 0..PERMUTATION_WIDTH {
                    output_state[i] = next_state[i];
                    if let Some(expected_output) = expected_output {
                        assert_eq!(expected_output[i], next_state[i]);
                    }
                }
            } else {
                external_rounds_state[r + 1] = next_state;
            }
        }
    }

    fn populate_external_round(
        &self,
        external_rounds_state: &[[F; PERMUTATION_WIDTH]],
        sbox: &mut Option<&mut [[F; PERMUTATION_WIDTH]; NUM_EXTERNAL_ROUNDS]>,
        r: usize,
    ) -> [F; PERMUTATION_WIDTH] {
        let mut state = {
            // For the first round, apply the linear layer.
            let round_state: &[F; PERMUTATION_WIDTH] = if r == 0 {
                &external_linear_layer_immut(&external_rounds_state[r])
            } else {
                &external_rounds_state[r]
            };

            // Add round constants.
            //
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, and instead include it in the constraint for the x^3 part of the
            // sbox.
            let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
                r
            } else {
                r + NUM_INTERNAL_ROUNDS
            };
            let mut add_rc = *round_state;
            for i in 0..PERMUTATION_WIDTH {
                add_rc[i] += F::from_wrapped_u32(RC_16_30_U32[round][i]);
            }

            // Apply the sbox.
            if F::field_type() == FieldType::TypeBabyBear {
                // BabyBear version
                let mut sbox_deg_7: [F; 16] = [F::ZERO; PERMUTATION_WIDTH];
                let mut sbox_deg_3: [F; 16] = [F::ZERO; PERMUTATION_WIDTH];
                for i in 0..PERMUTATION_WIDTH {
                    sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
                    sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
                }
                if let Some(sbox) = sbox.as_deref_mut() {
                    sbox[r] = sbox_deg_3;
                }

                sbox_deg_7
            } else if F::field_type() == FieldType::TypeKoalaBear {
                // KoalaBear version
                let mut sbox_deg_3: [F; 16] = [F::ZERO; PERMUTATION_WIDTH];
                for i in 0..PERMUTATION_WIDTH {
                    sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
                }
                if let Some(sbox) = sbox.as_deref_mut() {
                    sbox[r] = sbox_deg_3;
                }

                sbox_deg_3
            } else {
                panic!("Unsupported field type: {:?}", F::field_type());
            }
        };

        // Apply the linear layer.
        external_linear_layer(&mut state);
        state
    }

    fn populate_internal_rounds(
        &self,
        internal_rounds_state: &[F; PERMUTATION_WIDTH],
        internal_rounds_s0: &mut [F; NUM_INTERNAL_ROUNDS_MINUS_ONE],
        sbox: &mut Option<&mut [F; NUM_INTERNAL_ROUNDS]>,
    ) -> [F; PERMUTATION_WIDTH] {
        let mut state: [F; PERMUTATION_WIDTH] = *internal_rounds_state;
        let mut sbox_deg_3: [F; NUM_INTERNAL_ROUNDS] = [F::ZERO; NUM_INTERNAL_ROUNDS];
        for r in 0..NUM_INTERNAL_ROUNDS {
            // Add the round constant to the 0th state element.
            // Optimization: Since adding a constant is a degree 1 operation, we can avoid adding
            // columns for it, just like for external rounds.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = state[0] + F::from_wrapped_u32(RC_16_30_U32[round][0]);

            // Apply the sbox.
            if F::field_type() == FieldType::TypeBabyBear {
                sbox_deg_3[r] = add_rc * add_rc * add_rc;
                let sbox_deg_7 = sbox_deg_3[r] * sbox_deg_3[r] * add_rc;
                state[0] = sbox_deg_7;
            } else if F::field_type() == FieldType::TypeKoalaBear {
                sbox_deg_3[r] = add_rc * add_rc * add_rc;
                state[0] = sbox_deg_3[r];
            } else {
                panic!("Unsupported field type: {:?}", F::field_type());
            }

            internal_linear_layer::<F, _>(&mut state);

            // Optimization: since we're only applying the sbox to the 0th state element, we only
            // need to have columns for the 0th state element at every step. This is because the
            // linear layer is degree 1, so all state elements at the end can be expressed as a
            // degree-3 polynomial of the state at the beginning of the internal rounds and the 0th
            // state element at rounds prior to the current round
            if r < NUM_INTERNAL_ROUNDS - 1 {
                internal_rounds_s0[r] = state[0];
            }
        }

        let ret_state = state;

        if let Some(sbox) = sbox.as_deref_mut() {
            *sbox = sbox_deg_3;
        }

        ret_state
    }
}
