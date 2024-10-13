use crate::{
    chips::chips::alu::add_sub::{
        columns::{AddSubCols, NUM_ADD_SUB_COLS},
        AddSubChip,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::{
        events::{AluEvent, ByteLookupEvent, ByteRecordBehavior},
        record::EmulationRecord,
    },
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
};
use core::borrow::BorrowMut;
use hashbrown::HashMap;
use itertools::Itertools;
use log::debug;
use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};

impl<F: Field> BaseAir<F> for AddSubChip<F> {
    fn width(&self) -> usize {
        NUM_ADD_SUB_COLS
    }
}

impl<F: Field> ChipBehavior<F> for AddSubChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "AddSub".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        _output: &mut Self::Record,
    ) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let chunk_size = std::cmp::max(
            (input.add_events.len() + input.sub_events.len()) / num_cpus::get(),
            1,
        );
        let merged_events = input
            .add_events
            .iter()
            .chain(input.sub_events.iter())
            .collect::<Vec<_>>();

        let row_batches = merged_events
            .par_chunks(chunk_size)
            .map(|events| {
                let rows = events
                    .iter()
                    .map(|event| {
                        let mut row = [F::zero(); NUM_ADD_SUB_COLS];
                        let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                        let mut blu = Vec::new();
                        self.event_to_row(event, cols, &mut blu);
                        row
                    })
                    .collect::<Vec<_>>();
                rows
            })
            .collect::<Vec<_>>();

        let mut rows: Vec<[F; NUM_ADD_SUB_COLS]> = vec![];
        for row_batch in row_batches {
            rows.extend(row_batch);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ADD_SUB_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_ADD_SUB_COLS, F>(&mut trace.values);

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut AddSubCols<F> =
                trace.values[i * NUM_ADD_SUB_COLS..(i + 1) * NUM_ADD_SUB_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
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
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_ADD_SUB_COLS];
                    let cols: &mut AddSubCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        extra.add_chunked_byte_lookup_events(blu_batches.iter().collect_vec());

        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.add_events.is_empty() || !record.sub_events.is_empty()
    }
}

impl<F: Field> AddSubChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut AddSubCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let is_add = event.opcode == Opcode::ADD;
        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.is_add = F::from_bool(is_add);
        cols.is_sub = F::from_bool(!is_add);

        let operand_1 = if is_add { event.b } else { event.a };
        let operand_2 = event.c;

        cols.add_operation
            .populate(blu, event.chunk, event.channel, operand_1, operand_2);
        cols.operand_1 = Word::from(operand_1);
        cols.operand_2 = Word::from(operand_2);
    }
}
