use super::columns::NUM_SLL_COLS;
use crate::{
    chips::chips::{
        alu::{
            event::AluEvent,
            sll::{ShiftLeftValueCols, NUM_SLL_VALUE_COLS},
        },
        byte::event::ByteRecordBehavior,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
    primitives::consts::{BYTE_SIZE, SLL_DATAPAR, WORD_SIZE},
    recursion_v2::stark::utils::next_power_of_two,
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::{ParallelSlice, ParallelSliceMut},
};
use std::{borrow::BorrowMut, marker::PhantomData};
use tracing::debug;

#[derive(Default, Clone, Debug)]
pub struct SLLChip<F>(PhantomData<F>);

impl<F: Field> BaseAir<F> for SLLChip<F> {
    fn width(&self) -> usize {
        NUM_SLL_COLS
    }
}

impl<F: PrimeField> ChipBehavior<F> for SLLChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShiftLeft".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let events = input.shift_left_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(SLL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_SLL_COLS];

        let populate_len = events.len() * NUM_SLL_VALUE_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_SLL_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut ShiftLeftValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        let padded_row_template = {
            let mut row = [F::ZERO; NUM_SLL_VALUE_COLS];
            let cols: &mut ShiftLeftValueCols<F> = row.as_mut_slice().borrow_mut();
            cols.shift_by_n_bits[0] = F::ONE;
            cols.shift_by_n_bytes[0] = F::ONE;
            cols.bit_shift_multiplier = F::ONE;
            row
        };
        for i in populate_len..values.len() {
            values[i] = padded_row_template[i % NUM_SLL_VALUE_COLS];
        }

        RowMajorMatrix::new(values, NUM_SLL_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.shift_left_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .shift_left_events
            .par_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu_events = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = ShiftLeftValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu_events);
                });
                blu_events
            })
            .collect::<Vec<_>>();

        extra.add_byte_lookup_events(blu_batches);
        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.shift_left_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> SLLChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut ShiftLeftValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();
        cols.a = Word(a.map(F::from_canonical_u8));
        cols.b = Word(b.map(F::from_canonical_u8));
        cols.c = Word(c.map(F::from_canonical_u8));
        cols.is_real = F::ONE;

        for i in 0..BYTE_SIZE {
            // get c least 8 bits (a byte)
            cols.c_lsb[i] = F::from_canonical_u32((event.c >> i) & 1);
        }

        // c_slb 1th and 3th bits presents bits shift num
        let num_bits_to_shift = event.c as usize % BYTE_SIZE;
        for i in 0..BYTE_SIZE {
            cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
        }

        let bit_shift_multiplier = 1u32 << num_bits_to_shift;
        cols.bit_shift_multiplier = F::from_canonical_u32(bit_shift_multiplier);

        let mut carry = 0u32;
        let base = 1u32 << BYTE_SIZE;
        let mut shift_result = [0u8; WORD_SIZE];
        let mut shift_result_carry = [0u8; WORD_SIZE];
        for i in 0..WORD_SIZE {
            let v = b[i] as u32 * bit_shift_multiplier + carry;
            carry = v / base;
            shift_result[i] = (v % base) as u8;
            shift_result_carry[i] = carry as u8;
        }
        cols.shift_result = shift_result.map(F::from_canonical_u8);
        cols.shift_result_carry = shift_result_carry.map(F::from_canonical_u8);

        // c_slb 4th and 5th bits presents byte shift num, maximum is 4
        let num_bytes_to_shift = (event.c & 0b11111) as usize / BYTE_SIZE;
        for i in 0..WORD_SIZE {
            cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
        }

        blu.add_u8_range_checks(shift_result);
        blu.add_u8_range_checks(shift_result_carry);

        // Sanity check.
        for i in num_bytes_to_shift..WORD_SIZE {
            debug_assert_eq!(
                cols.shift_result[i - num_bytes_to_shift],
                F::from_canonical_u8(a[i])
            );
        }
    }
}
