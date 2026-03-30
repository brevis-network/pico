use crate::{
    chips::{
        chips::{alu::event::AluEvent, byte::event::ByteRecordBehavior},
        gadgets::msb::U16MSBGadget,
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::{u64_to_u16_limbs, SR_DATAPAR, WORD_SIZE},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::{borrow::BorrowMut, marker::PhantomData};

use super::columns::{ShiftRightValueCols, NUM_SLR_COLS, NUM_SLR_VALUE_COLS};

/// A chip that implements bitwise operations for the opcodes SRL, SRA, SRLW, and SRAW.
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

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let events = input.shift_right_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(SR_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_SLR_COLS];

        let populate_len = events.len() * NUM_SLR_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_SLR_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut ShiftRightValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        let padded_row_template = {
            let mut row = [F::ZERO; NUM_SLR_VALUE_COLS];
            let cols: &mut ShiftRightValueCols<F> = row.as_mut_slice().borrow_mut();
            cols.v_01 = F::from_canonical_u32(16);
            cols.v_012 = F::from_canonical_u32(256);
            cols.v_0123 = F::from_canonical_u32(65536);
            cols.c = F::ZERO;
            row
        };
        for i in populate_len..values.len() {
            values[i] = padded_row_template[i % NUM_SLR_VALUE_COLS];
        }

        RowMajorMatrix::new(values, NUM_SLR_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.shift_right_events.len() / num_cpus::get(), 1);

        let blu_events = input
            .shift_right_events
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = ShiftRightValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.shift_right_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: PrimeField32> ShiftRightChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut ShiftRightValueCols<F>,
        blu: &mut impl crate::chips::chips::byte::event::ByteRecordBehavior,
    ) {
        let a = event.a;
        let b = event.b;
        let c = event.c;

        // Set output operand
        cols.a = Word::from(a);

        // Set operand b (the value being shifted)
        cols.b = Word::from(b);

        // Set operand c (shift amount) for ALU lookup
        cols.c_for_lookup = Word::from(c);

        // Set opcode flags
        cols.is_srl = F::from_bool(event.opcode == Opcode::SRL);
        cols.is_sra = F::from_bool(event.opcode == Opcode::SRA);
        cols.is_srlw = F::from_bool(event.opcode == Opcode::SRLW);
        cols.is_sraw = F::from_bool(event.opcode == Opcode::SRAW);

        // Set c_bits (6 lowest bits of c)
        let c_val = u64_to_u16_limbs(c)[0];
        for i in 0..6 {
            cols.c_bits[i] = F::from_canonical_u16((c_val >> i) & 1);
        }
        cols.c = F::from_canonical_u16(c_val);
        blu.add_bit_range_check(c_val >> 6, 10);

        // Set v_01, v_012, v_0123
        cols.v_01 = F::from_canonical_u32(1 << (4 - (c_val & 3)));
        cols.v_012 = F::from_canonical_u32(1 << (8 - (c_val & 7)));
        cols.v_0123 = F::from_canonical_u32(1 << (16 - (c_val & 15)));

        // Convert b to u16 limbs
        let b_limbs = u64_to_u16_limbs(b);

        // Handle b_msb for SRA/SRAW
        if event.opcode == Opcode::SRA {
            // For 64-bit SRA, use the MSB of the highest limb (limb[3])
            let mut gadget = U16MSBGadget::default();
            gadget.populate(blu, b_limbs[3]);
            cols.b_msb.msb = gadget.msb;
        } else if event.opcode == Opcode::SRAW {
            // For 32-bit SRAW, use the MSB of limb[1] (second limb, which represents the high 16 bits of the 32-bit value)
            let mut gadget = U16MSBGadget::default();
            gadget.populate(blu, b_limbs[1]);
            cols.b_msb.msb = gadget.msb;
        } else {
            cols.b_msb.msb = F::ZERO;
        }
        cols.sra_msb_v0123 = cols.b_msb.msb * cols.v_0123;

        let is_word = event.opcode == Opcode::SRLW || event.opcode == Opcode::SRAW;
        let not_word = if is_word { 0u16 } else { 1u16 };

        // Handle srw_msb for word operations
        if is_word {
            // For word operations, get MSB of a's second limb (high 16 bits of 32-bit value)
            let a_limbs = u64_to_u16_limbs(a);
            let mut gadget = U16MSBGadget::default();
            gadget.populate(blu, a_limbs[1]);
            cols.srw_msb.msb = gadget.msb;
        } else {
            cols.srw_msb.msb = F::ZERO;
        }

        // Calculate bit shift
        let bit_shift = (c_val & 0xF) as u8;

        // Process each limb
        for i in 0..WORD_SIZE {
            let limb = b_limbs[i] as u32;
            let lower_limb_val = (limb & ((1 << bit_shift) - 1)) as u16;
            let higher_limb_val = (limb >> bit_shift) as u16;
            cols.lower_limb[i] = F::from_canonical_u16(lower_limb_val);
            cols.higher_limb[i] = F::from_canonical_u16(higher_limb_val);
            blu.add_bit_range_check(lower_limb_val, bit_shift);
            blu.add_bit_range_check(higher_limb_val, 16 - bit_shift);
        }

        // Calculate limb_result
        for i in 0..WORD_SIZE {
            cols.limb_result[i] = cols.higher_limb[i];
            if i != WORD_SIZE - 1 {
                cols.limb_result[i] +=
                    cols.lower_limb[i + 1] * F::from_canonical_u32(1 << (16 - bit_shift));
            }
        }

        // Calculate shift amount (which u16 limb to shift by)
        // For word ops: shift_amount = 0 or 1 (only 0-31 bits)
        // For 64-bit ops: shift_amount = 0, 1, 2, or 3 (0-63 bits)
        let shift_amount = ((c_val >> 4) & 1) + 2 * ((c_val >> 5) & 1) * not_word;

        let mut shift = [0u16; 4];
        for i in 0..4 {
            if i == shift_amount as usize {
                shift[i] = 1;
            }
        }
        cols.shift_u16 = shift.map(|x| F::from_canonical_u16(x));

        let is_w_imm = is_word && event.is_imm;
        cols.is_w_imm = F::from_bool(is_w_imm);
        cols.imm_c = F::from_bool(event.is_imm);
    }
}

impl<F> EventCapture for ShiftRightChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_shift_right_events += record.shift_right_events.len();
    }
}
