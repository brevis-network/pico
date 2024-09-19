use super::{
    columns::{BitwiseCols, NUM_BITWISE_COLS},
    BitwiseChip,
};
use core::borrow::BorrowMut;
use hashbrown::HashMap;
use itertools::Itertools;
use log::info;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::{IntoParallelRefIterator, ParallelIterator, ParallelSlice};
use pico_compiler::opcode::{ByteOpcode, Opcode};
use pico_emulator::riscv::{
    events::{AluEvent, ByteLookupEvent, ByteRecord},
    record::EmulationRecord,
};
use pico_machine::{chip::ChipBehavior, utils::pad_to_power_of_two, word::Word};

impl<F: Field> ChipBehavior<F> for BitwiseChip<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord) -> RowMajorMatrix<F> {
        info!("BitwiseChip - generate_main: BEGIN");

        let rows = input
            .bitwise_events
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_BITWISE_COLS];
                let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                let mut blu = Vec::new();
                self.event_to_row(event, cols, &mut blu);
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BITWISE_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_BITWISE_COLS, F>(&mut trace.values);

        for i in 0..trace.height() {
            let cols: &mut BitwiseCols<F> =
                trace.values[i * NUM_BITWISE_COLS..(i + 1) * NUM_BITWISE_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        info!("BitwiseChip - generate_main: END");

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        info!("BitwiseChip - extra_record: BEGIN");

        let chunk_size = std::cmp::max(input.bitwise_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .bitwise_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_BITWISE_COLS];
                    let cols: &mut BitwiseCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        extra.add_sharded_byte_lookup_events(blu_batches.iter().collect_vec());

        info!("BitwiseChip - extra_record: END");
    }
}

impl<F: Field> BitwiseChip<F> {
    /// Create a row from an event.
    fn event_to_row(&self, event: &AluEvent, cols: &mut BitwiseCols<F>, blu: &mut impl ByteRecord) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.a = Word::from(event.a);
        cols.b = Word::from(event.b);
        cols.c = Word::from(event.c);

        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);

        for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
            let byte_event = ByteLookupEvent {
                shard: event.shard,
                channel: event.channel,
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
