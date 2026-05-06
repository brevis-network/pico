use crate::{
    chips::{
        chips::{
            alu::{
                addw::{
                    columns::{AddwValueCols, NUM_ADDW_COLS, NUM_ADDW_VALUE_COLS},
                    AddwChip,
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

impl<F: PrimeField32> ChipBehavior<F> for AddwChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Addw".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events: Vec<&AluEvent> = input
            .add_events
            .iter()
            .filter(|e| e.opcode == Opcode::ADDW)
            .collect();

        let nrows = events.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_ADDW_COLS];

        let populate_len = events.len() * NUM_ADDW_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_ADDW_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut AddwValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_ADDW_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events: Vec<&AluEvent> = input
            .add_events
            .iter()
            .filter(|e| e.opcode == Opcode::ADDW)
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .pico_bridge()
            .flat_map(|chunk| {
                let mut blu = vec![];
                chunk.iter().for_each(|event| {
                    let mut dummy = AddwValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.add_events.iter().any(|e| e.opcode == Opcode::ADDW)
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> AddwChip<F> {
    /// Populate a single trace row from an ADDW event.
    ///
    /// Computes `lower32 = (b as u32).wrapping_add(c as u32)`, stores it as two u16 limbs,
    /// and records the MSB for sign extension.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut AddwValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_addw = F::ONE;
        cols.addw_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
