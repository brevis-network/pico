use crate::{
    chips::chips::sll::columns::{ShiftLeftCols, NUM_SLL_COLS},
    compiler::{
        riscv::program::Program,
        word::{Word, BYTE_SIZE, WORD_SIZE},
    },
    emulator::riscv::{
        events::{AluEvent, ByteLookupEvent, ByteRecordBehavior},
        record::EmulationRecord,
    },
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
};
use hashbrown::HashMap;
use itertools::Itertools;
use log::debug;
use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use std::{borrow::BorrowMut, marker::PhantomData};

#[derive(Default, Clone, Debug)]
pub struct SLLChip<F>(PhantomData<F>);

impl<F: Field> BaseAir<F> for SLLChip<F> {
    fn width(&self) -> usize {
        NUM_SLL_COLS
    }
}

impl<F: Field> ChipBehavior<F> for SLLChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShiftLeft".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = input.shift_left_events.clone().len();
        let mut trace = RowMajorMatrix::new(vec![F::zero(); NUM_SLL_COLS * rows], NUM_SLL_COLS);
        trace
            .rows_mut()
            .zip(input.shift_left_events.clone())
            .for_each(|(row, event)| {
                let cols: &mut ShiftLeftCols<F> = row.borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(&event, cols, &mut blu);
            });
        pad_to_power_of_two::<NUM_SLL_COLS, F>(&mut trace.values);

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::zero(); NUM_SLL_COLS];
            let cols: &mut ShiftLeftCols<F> = row.as_mut_slice().borrow_mut();
            cols.shift_by_n_bits[0] = F::one();
            cols.shift_by_n_bytes[0] = F::one();
            cols.bit_shift_multiplier = F::one();
            row
        };
        debug_assert!(padded_row_template.len() == NUM_SLL_COLS);
        for i in rows.clone() * NUM_SLL_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_SLL_COLS];
        }

        for i in 0..trace.height() {
            let cols: &mut ShiftLeftCols<F> =
                trace.values[i * NUM_SLL_COLS..(i + 1) * NUM_SLL_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.shift_left_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .shift_left_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_SLL_COLS];
                    let cols: &mut ShiftLeftCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        extra.add_chunked_byte_lookup_events(blu_batches.iter().collect_vec());
        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.shift_left_events.is_empty()
    }
}

impl<F: Field> SLLChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut ShiftLeftCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();
        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.a = Word(a.map(F::from_canonical_u8));
        cols.b = Word(b.map(F::from_canonical_u8));
        cols.c = Word(c.map(F::from_canonical_u8));
        cols.is_real = F::one();

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

        blu.add_u8_range_checks(event.chunk, event.channel, &shift_result);
        blu.add_u8_range_checks(event.chunk, event.channel, &shift_result_carry);

        // Sanity check.
        for i in num_bytes_to_shift..WORD_SIZE {
            debug_assert_eq!(
                cols.shift_result[i - num_bytes_to_shift],
                F::from_canonical_u8(a[i])
            );
        }
    }
}
