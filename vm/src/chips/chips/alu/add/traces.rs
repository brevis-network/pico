use crate::{
    chips::{
        chips::{
            alu::{
                add::{
                    columns::{AddValueCols, NUM_ADD_COLS, NUM_ADD_VALUE_COLS},
                    AddChip,
                },
                event::AluEvent,
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

impl<F: PrimeField32> ChipBehavior<F> for AddChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Add".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events: Vec<&AluEvent> = input
            .add_events
            .iter()
            .filter(|e| e.opcode == Opcode::ADD)
            .collect();

        let nrows = events.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_ADD_COLS];

        let populate_len = events.len() * NUM_ADD_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_ADD_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut AddValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_ADD_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events: Vec<&AluEvent> = input
            .add_events
            .iter()
            .filter(|e| e.opcode == Opcode::ADD)
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .pico_bridge()
            .flat_map(|chunk| {
                let mut blu = vec![];
                chunk.iter().for_each(|event| {
                    let mut dummy = AddValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.add_events.iter().any(|e| e.opcode == Opcode::ADD)
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> AddChip<F> {
    /// Populate a single trace row from an ADD event.
    ///
    /// `operand_1` = `b`, `operand_2` = `c`, result = `b + c` = `a` (mod 2^64).
    /// Values are stored as four u16 limbs (little-endian) to match `Add64Gadget`.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut AddValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_add = F::ONE;
        cols.add_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
