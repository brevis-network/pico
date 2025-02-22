use super::{columns::NUM_BITWISE_COLS, BitwiseChip};
use crate::{
    chips::{
        chips::{
            alu::{
                bitwise::columns::{BitwiseValueCols, NUM_BITWISE_VALUE_COLS},
                event::AluEvent,
            },
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            program::Program,
        },
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::BITWISE_DATAPAR,
};
use core::borrow::BorrowMut;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

impl<F: PrimeField32> ChipBehavior<F> for BitwiseChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let events = input.bitwise_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(BITWISE_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_BITWISE_COLS];

        let populate_len = events.len() * NUM_BITWISE_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_BITWISE_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut BitwiseValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_BITWISE_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.bitwise_events.len() / num_cpus::get(), 1);

        let blu_events = input
            .bitwise_events
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = BitwiseValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_events);
    }

    // flag reflecting whether chip is used in the record
    fn is_active(&self, record: &Self::Record) -> bool {
        !record.bitwise_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> BitwiseChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut BitwiseValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);

        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);

        for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::from(event.opcode),
                a1: b_a as u16,
                a2: 0,
                b: b_b,
                c: b_c,
            };
            blu.add_byte_lookup_event(byte_event);
        }
    }
}
