use super::columns::{ShiftRightCols, NUM_SLR_COLS};
use crate::{
    chips::chips::{
        alu::event::AluEvent,
        byte::{
            event::{ByteLookupEvent, ByteRecordBehavior},
            utils::shr_carry,
        },
        rangecheck::event::{RangeLookupEvent, RangeRecordBehavior},
    },
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            program::Program,
        },
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
    primitives::consts::{BYTE_SIZE, LONG_WORD_SIZE, WORD_SIZE},
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use std::{borrow::BorrowMut, marker::PhantomData};
use tracing::debug;

/// A chip that implements bitwise operations for the opcodes SRL and SRA.
#[derive(Default)]
pub struct ShiftRightChip<F>(PhantomData<F>);

impl<F: Field> BaseAir<F> for ShiftRightChip<F> {
    fn width(&self) -> usize {
        NUM_SLR_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShiftRightChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShiftRight".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _: &mut EmulationRecord,
    ) -> p3_matrix::dense::RowMajorMatrix<F> {
        let rows = input.shift_right_events.clone().len();
        let mut trace = RowMajorMatrix::new(vec![F::ZERO; NUM_SLR_COLS * rows], NUM_SLR_COLS);
        trace
            .rows_mut()
            .zip(input.shift_right_events.clone())
            .for_each(|(row, event)| {
                let cols: &mut ShiftRightCols<F> = row.borrow_mut();
                self.event_to_row(&event, cols, &mut (), &mut ());
            });

        // Pad the trace based on shape
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_SLR_COLS, F>(&mut trace.values, log_rows);

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::ZERO; NUM_SLR_COLS];
            let cols: &mut ShiftRightCols<F> = row.as_mut_slice().borrow_mut();
            // Shift 0 by 0 bits and 0 bytes.
            // cols.is_srl = F::ONE;
            cols.shift_by_n_bits[0] = F::ONE;
            cols.shift_by_n_bytes[0] = F::ONE;
            row
        };

        debug_assert!(padded_row_template.len() == NUM_SLR_COLS);
        for i in rows * NUM_SLR_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_SLR_COLS];
        }

        for i in 0..trace.height() {
            let cols: &mut ShiftRightCols<F> =
                trace.values[i * NUM_SLR_COLS..(i + 1) * NUM_SLR_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.shift_right_events.len() / num_cpus::get(), 1);

        let (blu_batches, range_batches): (Vec<_>, Vec<_>) = input
            .shift_right_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                let mut range: HashMap<RangeLookupEvent, usize> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::ZERO; NUM_SLR_COLS];
                    let cols: &mut ShiftRightCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu, &mut range);
                });
                (blu, range)
            })
            .unzip();

        extra.add_chunked_byte_lookup_events(blu_batches.iter().collect_vec());
        extra.add_rangecheck_lookup_events(range_batches);
        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.shift_right_events.is_empty()
    }
}

impl<F: PrimeField32> ShiftRightChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut ShiftRightCols<F>,
        blu: &mut impl ByteRecordBehavior,
        range: &mut impl RangeRecordBehavior,
    ) {
        // Initialize cols with basic operands and flags derived from the current event.
        {
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.a = Word::from(event.a);
            cols.b = Word::from(event.b);
            cols.c = Word::from(event.c);

            cols.b_msb = F::from_canonical_u32((event.b >> 31) & 1);

            cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
            cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);

            cols.is_real = F::ONE;

            for i in 0..BYTE_SIZE {
                cols.c_least_sig_byte[i] = F::from_canonical_u32((event.c >> i) & 1);
            }

            // Insert the MSB lookup event.
            let most_significant_byte = event.b.to_le_bytes()[WORD_SIZE - 1];
            blu.add_byte_lookup_events(vec![ByteLookupEvent {
                chunk: event.chunk,
                opcode: ByteOpcode::MSB,
                a1: ((most_significant_byte >> 7) & 1) as u16,
                a2: 0,
                b: most_significant_byte,
                c: 0,
            }]);
        }

        let num_bytes_to_shift = (event.c % 32) as usize / BYTE_SIZE;
        let num_bits_to_shift = (event.c % 32) as usize % BYTE_SIZE;

        // Byte shifting.
        let mut byte_shift_result = [0u8; LONG_WORD_SIZE];
        {
            for i in 0..WORD_SIZE {
                cols.shift_by_n_bytes[i] = F::from_bool(num_bytes_to_shift == i);
            }
            let sign_extended_b = {
                if event.opcode == Opcode::SRA {
                    // Sign extension is necessary only for arithmetic right shift.
                    ((event.b as i32) as i64).to_le_bytes()
                } else {
                    (event.b as u64).to_le_bytes()
                }
            };

            for i in 0..LONG_WORD_SIZE {
                if i + num_bytes_to_shift < LONG_WORD_SIZE {
                    byte_shift_result[i] = sign_extended_b[i + num_bytes_to_shift];
                }
            }
            cols.byte_shift_result = byte_shift_result.map(F::from_canonical_u8);
        }

        // Bit shifting.
        {
            for i in 0..BYTE_SIZE {
                cols.shift_by_n_bits[i] = F::from_bool(num_bits_to_shift == i);
            }
            let carry_multiplier = 1 << (8 - num_bits_to_shift);
            let mut last_carry = 0u32;
            let mut bit_shift_result = [0u8; LONG_WORD_SIZE];
            let mut shr_carry_output_carry = [0u8; LONG_WORD_SIZE];
            let mut shr_carry_output_shifted_byte = [0u8; LONG_WORD_SIZE];
            for i in (0..LONG_WORD_SIZE).rev() {
                let (shift, carry) = shr_carry(byte_shift_result[i], num_bits_to_shift as u8);

                let byte_event = ByteLookupEvent {
                    chunk: event.chunk,
                    opcode: ByteOpcode::ShrCarry,
                    a1: shift as u16,
                    a2: carry,
                    b: byte_shift_result[i],
                    c: num_bits_to_shift as u8,
                };
                blu.add_byte_lookup_event(byte_event);

                shr_carry_output_carry[i] = carry;
                shr_carry_output_shifted_byte[i] = shift;
                bit_shift_result[i] = ((shift as u32 + last_carry * carry_multiplier) & 0xff) as u8;
                last_carry = carry as u32;
            }
            cols.bit_shift_result = bit_shift_result.map(F::from_canonical_u8);
            cols.shr_carry_output_carry = shr_carry_output_carry.map(F::from_canonical_u8);
            cols.shr_carry_output_shifted_byte =
                shr_carry_output_shifted_byte.map(F::from_canonical_u8);
            for i in 0..WORD_SIZE {
                debug_assert_eq!(cols.a[i], cols.bit_shift_result[i].clone());
            }

            let chunk = event.chunk;
            range.add_u8_range_checks(byte_shift_result, Some(chunk));
            range.add_u8_range_checks(bit_shift_result, Some(chunk));
            range.add_u8_range_checks(shr_carry_output_carry, Some(chunk));
            range.add_u8_range_checks(shr_carry_output_shifted_byte, Some(chunk));
        }
    }
}
