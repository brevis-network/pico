use super::columns::NUM_SLL_COLS;
use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                sll::{ShiftLeftValueCols, NUM_SLL_VALUE_COLS},
            },
            byte::event::ByteRecordBehavior,
        },
        utils::next_power_of_two,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{SLL_DATAPAR, WORD_SIZE},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    compiler::riscv::opcode::Opcode,
    machine::estimator::{EventCapture, EventSizeCapture},
    primitives::consts::{u32_to_u16_limbs, u64_to_u16_limbs},
};
use std::{borrow::BorrowMut, marker::PhantomData};

#[derive(Default, Clone, Debug)]
pub struct SLLChip<F>(PhantomData<F>);

impl<F: Field> BaseAir<F> for SLLChip<F> {
    fn width(&self) -> usize {
        NUM_SLL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for SLLChip<F> {
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
            .pico_chunks_mut(NUM_SLL_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut ShiftLeftValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        let padded_row_template = {
            let mut row = [F::ZERO; NUM_SLL_VALUE_COLS];
            let cols: &mut ShiftLeftValueCols<F> = row.as_mut_slice().borrow_mut();
            cols.v_01 = F::ONE;
            cols.v_012 = F::ONE;
            cols.v_0123 = F::ONE;
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
            .pico_chunks(chunk_size)
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
        let c = u64_to_u16_limbs(event.c)[0];

        if event.opcode == Opcode::SLLW {
            let sllw_val = ((event.b as i64) << (c & 0x1f)) as u32;
            let sllw_limbs = u32_to_u16_limbs(sllw_val);
            cols.sllw_msb.populate(blu, sllw_limbs[1]);
        } else {
            cols.sllw_msb.msb = F::ZERO;
        }

        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);
        let is_sll = event.opcode == Opcode::SLL;
        cols.is_sll = F::from_bool(is_sll);

        cols.is_sllw = F::from_bool(event.opcode == Opcode::SLLW);

        for i in 0..6 {
            cols.c_bits[i] = F::from_canonical_u16((c >> i) & 1);
        }
        blu.add_bit_range_check(c >> 6, 10);

        cols.v_01 = F::from_canonical_u16(1 << (c & 3));
        cols.v_012 = F::from_canonical_u16(1 << (c & 7));
        cols.v_0123 = F::from_canonical_u16(1 << (c & 15));

        let shift_amount = ((c >> 4) & 1) + 2 * ((c >> 5) & 1) * (is_sll as u16);

        let mut shift = [0u16; 4];
        for i in 0..4 {
            if i == shift_amount as usize {
                shift[i] = 1;
            }
        }

        let b = u64_to_u16_limbs(event.b);
        let bit_shift = (c & 0xF) as u8;
        for i in 0..WORD_SIZE {
            let limb = b[i] as u32;
            let lower_limb = (limb & ((1 << (16 - bit_shift)) - 1)) as u16;
            let higher_limb = (limb >> (16 - bit_shift)) as u16;
            cols.lower_limb[i] = F::from_canonical_u16(lower_limb);
            cols.higher_limb[i] = F::from_canonical_u16(higher_limb);
            blu.add_bit_range_check(lower_limb, 16 - bit_shift);
            blu.add_bit_range_check(higher_limb, bit_shift);
        }

        for i in 0..WORD_SIZE {
            cols.limb_result[i] = cols.lower_limb[i] * F::from_canonical_u32(1u32 << bit_shift);
            if i != 0 {
                cols.limb_result[i] += cols.higher_limb[i - 1];
            }
        }

        cols.shift_u16 = shift.map(|x| F::from_canonical_u16(x));
    }
}

impl<F> EventCapture for SLLChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_shift_left_events += record.shift_left_events.len();
    }
}
