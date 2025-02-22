use crate::{
    chips::{
        chips::{
            poseidon2::{Poseidon2Chip, POSEIDON2_CHIPNAME},
            recursion_memory::MemoryAccessCols,
        },
        gadgets::poseidon2::{
            columns::{
                Poseidon2PreprocessedValueCols, Poseidon2ValueCols, NUM_POSEIDON2_COLS,
                NUM_POSEIDON2_VALUE_COLS, NUM_PREPROCESSED_POSEIDON2_COLS,
                NUM_PREPROCESSED_POSEIDON2_VALUE_COLS,
            },
            traces::populate_perm,
        },
        utils::next_power_of_two,
    },
    compiler::recursion::{instruction::Instruction::Poseidon2, program::RecursionProgram},
    configs::config::Poseidon2Config,
    emulator::recursion::emulator::RecursionRecord,
    iter::{join, IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR},
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::BorrowMut;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > ChipBehavior<F> for Poseidon2Chip<F, LinearLayers, Config>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        POSEIDON2_CHIPNAME.to_string()
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
            .pico_chunks_mut(NUM_PREPROCESSED_POSEIDON2_VALUE_COLS)
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

        let mut values = vec![F::ZERO; padded_nrows * NUM_POSEIDON2_COLS::<Config>];

        let populate_len = events.len() * NUM_POSEIDON2_VALUE_COLS::<Config>;
        let (values_pop, values_dummy) = values.split_at_mut(populate_len);
        join(
            || {
                values_pop
                    .pico_chunks_mut(NUM_POSEIDON2_VALUE_COLS::<Config>)
                    .zip_eq(events)
                    .for_each(|(row, event)| {
                        let cols: &mut Poseidon2ValueCols<F, Config> = row.borrow_mut();
                        populate_perm::<F, LinearLayers, Config>(
                            F::ONE,
                            cols,
                            event.input,
                            Some(event.output),
                            &self.constants,
                        );
                    });
            },
            || {
                let mut dummy = vec![F::ZERO; NUM_POSEIDON2_VALUE_COLS::<Config>];
                let dummy = dummy.as_mut_slice();
                let dummy_cols: &mut Poseidon2ValueCols<F, Config> = dummy.borrow_mut();
                populate_perm::<F, LinearLayers, Config>(
                    F::ZERO,
                    dummy_cols,
                    [F::ZERO; PERMUTATION_WIDTH],
                    None,
                    &self.constants,
                );
                values_dummy
                    .pico_chunks_mut(NUM_POSEIDON2_VALUE_COLS::<Config>)
                    .for_each(|row| row.copy_from_slice(dummy))
            },
        );

        RowMajorMatrix::new(values, NUM_POSEIDON2_COLS::<Config>)
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
