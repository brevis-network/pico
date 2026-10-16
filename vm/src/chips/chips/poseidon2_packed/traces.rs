use crate::{
    chips::{
        chips::{
            poseidon2_packed::{
                columns::{
                    Poseidon2PackedPreprocessedCols, NUM_POSEIDON2_PACKED_PREPROCESSED_COLS,
                },
                Poseidon2PackedChip, POSEIDON2_PACKED_CHIPNAME,
            },
            recursion_memory::MemoryAccessCols,
        },
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS},
            traces::populate_perm,
        },
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::Poseidon2PackedInstr,
    },
    configs::config::Poseidon2Config,
    emulator::recursion::emulator::RecursionRecord,
    iter::{join, IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::BorrowMut;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
    > ChipBehavior<F> for Poseidon2PackedChip<F, LinearLayers, Config>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        POSEIDON2_PACKED_CHIPNAME.to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_POSEIDON2_PACKED_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().poseidon2_packed,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_POSEIDON2_PACKED_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::Poseidon2Packed(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &Poseidon2PackedInstr<F>| {
                let mut row = [F::ZERO; NUM_POSEIDON2_PACKED_PREPROCESSED_COLS];
                let cols: &mut Poseidon2PackedPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.input = instr.input_addrs;
                cols.output = std::array::from_fn(|j| MemoryAccessCols {
                    addr: instr.output_addrs[j],
                    mult: instr.mults[j],
                });
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_POSEIDON2_PACKED_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_POSEIDON2_PACKED_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.poseidon2_packed_events;
        let nrows = events.len();
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_POSEIDON2_VALUE_COLS::<Config>];

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

        RowMajorMatrix::new(values, NUM_POSEIDON2_VALUE_COLS::<Config>)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
