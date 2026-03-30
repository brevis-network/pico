use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                sub::{
                    columns::{SubValueCols, NUM_SUB_COLS, NUM_SUB_VALUE_COLS},
                    SubChip,
                },
            },
            byte::event::ByteRecordBehavior,
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoBridge, PicoIterator, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::ADD_DATAPAR,
};
use core::borrow::BorrowMut;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

impl<F: PrimeField32> ChipBehavior<F> for SubChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Sub".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events: Vec<&AluEvent> = input
            .sub_events
            .iter()
            .filter(|e| e.opcode == Opcode::SUB)
            .collect();

        let nrows = events.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_SUB_COLS];

        let populate_len = events.len() * NUM_SUB_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_SUB_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut SubValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_SUB_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events: Vec<&AluEvent> = input
            .sub_events
            .iter()
            .filter(|e| e.opcode == Opcode::SUB)
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .pico_bridge()
            .flat_map(|chunk| {
                let mut blu = vec![];
                chunk.iter().for_each(|event| {
                    let mut dummy = SubValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.sub_events.iter().any(|e| e.opcode == Opcode::SUB)
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> SubChip<F> {
    /// Populate a single trace row from a SUB event.
    ///
    /// `operand_1` = `b` (minuend), `operand_2` = `c` (subtrahend),
    /// result = `b - c` = `a` (mod 2^64).
    /// Values are stored as four u16 limbs (little-endian) to match `Sub64Gadget`.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut SubValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_sub = F::ONE;
        cols.sub_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
