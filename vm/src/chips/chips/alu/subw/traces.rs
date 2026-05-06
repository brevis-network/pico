use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                subw::{
                    columns::{SubwValueCols, NUM_SUBW_COLS, NUM_SUBW_VALUE_COLS},
                    SubwChip,
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

impl<F: PrimeField32> ChipBehavior<F> for SubwChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Subw".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events: Vec<&AluEvent> = input
            .sub_events
            .iter()
            .filter(|e| e.opcode == Opcode::SUBW)
            .collect();

        let nrows = events.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_SUBW_COLS];

        let populate_len = events.len() * NUM_SUBW_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_SUBW_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut SubwValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_SUBW_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let events: Vec<&AluEvent> = input
            .sub_events
            .iter()
            .filter(|e| e.opcode == Opcode::SUBW)
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .pico_bridge()
            .flat_map(|chunk| {
                let mut blu = vec![];
                chunk.iter().for_each(|event| {
                    let mut dummy = SubwValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        record.sub_events.iter().any(|e| e.opcode == Opcode::SUBW)
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F: Field> SubwChip<F> {
    /// Populate a single trace row from a SUBW event.
    ///
    /// Computes `(b as i32).wrapping_sub(c as i32)` sign-extended to u64,
    /// stores lower 32 bits as two u16 limbs and records the MSB for sign extension.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut SubwValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_subw = F::ONE;
        cols.subw_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
