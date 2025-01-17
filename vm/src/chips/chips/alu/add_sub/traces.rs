use crate::{
    chips::chips::{
        alu::{
            add_sub::{
                columns::{AddSubValueCols, NUM_ADD_SUB_COLS, NUM_ADD_SUB_VALUE_COLS},
                AddSubChip,
            },
            event::AluEvent,
        },
        byte::event::ByteRecordBehavior,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
    primitives::consts::ADD_SUB_DATAPAR,
    recursion_v2::stark::utils::next_power_of_two,
};
use core::borrow::BorrowMut;
use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use rayon::{iter::IndexedParallelIterator, slice::ParallelSliceMut};
use tracing::debug;

impl<F: PrimeField> ChipBehavior<F> for AddSubChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "AddSub".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = input
            .add_events
            .iter()
            .chain(input.sub_events.iter())
            .collect::<Vec<_>>();
        let nrows = events.len().div_ceil(ADD_SUB_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_ADD_SUB_COLS];

        let populate_len = events.len() * NUM_ADD_SUB_VALUE_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_ADD_SUB_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut AddSubValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_ADD_SUB_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(
            (input.add_events.len() + input.sub_events.len()) / num_cpus::get(),
            1,
        );

        let event_iter = input
            .add_events
            .chunks(chunk_size)
            .chain(input.sub_events.chunks(chunk_size));

        let blu_batches = event_iter
            .par_bridge()
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = AddSubValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_batches);

        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.add_events.is_empty() || !record.sub_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> AddSubChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut AddSubValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let is_add = event.opcode == Opcode::ADD;
        cols.is_add = F::from_bool(is_add);
        cols.is_sub = F::from_bool(!is_add);

        let operand_1 = if is_add { event.b } else { event.a };
        let operand_2 = event.c;

        cols.add_operation.populate(blu, operand_1, operand_2);
        cols.operand_1 = Word::from(operand_1);
        cols.operand_2 = Word::from(operand_2);
    }
}
