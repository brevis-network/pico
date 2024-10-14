use super::columns::{LtCols, NUM_LT_COLS};
use crate::{
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            program::Program,
        },
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
use itertools::{izip, Itertools};
use log::debug;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use rayon::prelude::*;
use std::marker::PhantomData;

/// Lt Chip for proving U32 Signed/Unsigned b < c
#[derive(Default, Clone, Debug)]
pub struct LtChip<F>(PhantomData<F>);

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
        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_LT_COLS * input.clone().lt_events.len()],
            NUM_LT_COLS,
        );

        trace
            .par_rows_mut()
            .zip_eq(input.lt_events.clone())
            .for_each(|(row, event)| {
                let mut new_byte_lookup_events: Vec<ByteLookupEvent> = Vec::new();
                let cols: &mut LtCols<F> = row.borrow_mut();
                self.event_to_row(&event, cols, &mut new_byte_lookup_events);
            });

        pad_to_power_of_two::<NUM_LT_COLS, F>(&mut trace.values);

        // assign nonce to the trace.
        for i in 0..trace.height() {
            let cols: &mut LtCols<F> =
                trace.values[i * NUM_LT_COLS..(i + 1) * NUM_LT_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.lt_events.len() / num_cpus::get(), 1);

        let blu_batches = input
            .lt_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut blu: HashMap<u32, HashMap<ByteLookupEvent, usize>> = HashMap::new();
                events.iter().for_each(|event| {
                    let mut row = [F::zero(); NUM_LT_COLS];
                    let cols: &mut LtCols<F> = row.as_mut_slice().borrow_mut();
                    self.event_to_row(event, cols, &mut blu);
                });
                blu
            })
            .collect::<Vec<_>>();

        extra.add_chunked_byte_lookup_events(blu_batches.iter().collect_vec());
        debug!("{} chip - extra_record", self.name());
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.lt_events.is_empty()
    }
}

impl<F: PrimeField32> LtChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut LtCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.chunk = F::from_canonical_u32(event.chunk);
        cols.channel = F::from_canonical_u8(event.channel);
        cols.a = Word(a.map(F::from_canonical_u8));
        cols.b = Word(b.map(F::from_canonical_u8));
        cols.c = Word(c.map(F::from_canonical_u8));

        // If this is SLT, mask the MSB of b & c before computing cols.bits.
        let masked_b = b[3] & 0x7f;
        let masked_c = c[3] & 0x7f;
        cols.b_masked = F::from_canonical_u8(masked_b);
        cols.c_masked = F::from_canonical_u8(masked_c);

        cols.bit_b = cols.msb_b * cols.is_slt;
        cols.bit_c = cols.msb_c * cols.is_slt;

        // Send the masked interaction.
        blu.add_byte_lookup_event(ByteLookupEvent {
            chunk: event.chunk,
            channel: event.channel,
            opcode: ByteOpcode::AND,
            a1: masked_b as u16,
            a2: 0,
            b: b[3],
            c: 0x7f,
        });
        blu.add_byte_lookup_event(ByteLookupEvent {
            chunk: event.chunk,
            channel: event.channel,
            opcode: ByteOpcode::AND,
            a1: masked_c as u16,
            a2: 0,
            b: c[3],
            c: 0x7f,
        });

        let mut b_comp = b;
        let mut c_comp = c;
        if event.opcode == Opcode::SLT {
            b_comp[3] = masked_b;
            c_comp[3] = masked_c;
        }
        cols.slt_u = F::from_bool(b_comp < c_comp);
        cols.is_cmp_eq = F::from_bool(b_comp == c_comp);

        // Set the byte equality flags.
        for (b_byte, c_byte, flag) in izip!(
            b_comp.iter().rev(),
            c_comp.iter().rev(),
            cols.byte_flags.iter_mut().rev()
        ) {
            if c_byte != b_byte {
                *flag = F::one();
                cols.slt_u = F::from_bool(b_byte < c_byte);
                let b_byte = F::from_canonical_u8(*b_byte);
                let c_byte = F::from_canonical_u8(*c_byte);
                cols.not_eq_inv = (b_byte - c_byte).inverse();
                cols.cmp_bytes = [b_byte, c_byte];
                break;
            }
        }

        cols.msb_b = F::from_canonical_u8((b[3] >> 7) & 1);
        cols.msb_c = F::from_canonical_u8((c[3] >> 7) & 1);
        cols.is_sign_bit_same = if event.opcode == Opcode::SLT {
            F::from_bool((b[3] >> 7) == (c[3] >> 7))
        } else {
            F::one()
        };

        cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
        cols.is_slt_u = F::from_bool(event.opcode == Opcode::SLTU);

        // when case msb_b = 0; msb_c = 1(negative), a0 = 0;
        // when case msb_b = 1(negative); msg_c = 0, a0 = 1;
        // when case msb_b and msb_c both is 0 or 1, a0 depends on SLTU.
        assert_eq!(
            cols.a[0],
            cols.msb_b * cols.is_slt * (F::one() - cols.msb_c * cols.is_slt)
                + cols.is_sign_bit_same * cols.slt_u
        );

        blu.add_byte_lookup_event(ByteLookupEvent {
            chunk: event.chunk,
            channel: event.channel,
            opcode: ByteOpcode::LTU,
            a1: cols.slt_u.as_canonical_u32() as u16,
            a2: 0,
            b: cols.cmp_bytes[0].as_canonical_u32() as u8,
            c: cols.cmp_bytes[1].as_canonical_u32() as u8,
        });
    }
}
