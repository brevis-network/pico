use super::columns::{LtValueCols, NUM_LT_COLS, NUM_LT_VALUE_COLS};
use crate::{
    chips::{
        chips::{alu::event::AluEvent, byte::event::ByteRecordBehavior},
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{u64_to_u16_limbs, LT_DATAPAR},
};
use core::borrow::BorrowMut;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

/// Lt Chip for proving U32/U64 Signed/Unsigned b < c
#[derive(Default, Clone, Debug)]
pub struct LtChip<F>(std::marker::PhantomData<F>);

impl<F: Field> BaseAir<F> for LtChip<F> {
    fn width(&self) -> usize {
        NUM_LT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for LtChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "LessThan".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = input.lt_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(LT_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_LT_COLS];

        let populate_len = events.len() * NUM_LT_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_LT_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut LtValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_LT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.lt_events.len() / num_cpus::get(), 1);

        let blu_events = input
            .lt_events
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = LtValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.lt_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: PrimeField32> LtChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut LtValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a_u64 = event.a;
        let b_u64 = event.b;
        let c_u64 = event.c;

        // Set the input/output words using u16 limbs
        let a_limbs = u64_to_u16_limbs(a_u64);
        let b_limbs = u64_to_u16_limbs(b_u64);
        let c_limbs = u64_to_u16_limbs(c_u64);

        cols.a = Word(a_limbs.map(F::from_canonical_u16));
        cols.b = Word(b_limbs.map(F::from_canonical_u16));
        cols.c = Word(c_limbs.map(F::from_canonical_u16));

        // Set the opcode selectors
        let is_signed = event.opcode == Opcode::SLT;
        cols.is_slt = F::from_bool(is_signed);
        cols.is_slt_u = F::from_bool(event.opcode == Opcode::SLTU);

        // Populate the signed less-than gadget
        cols.lt_signed
            .populate_signed(blu, a_u64, b_u64, c_u64, is_signed);
    }
}
