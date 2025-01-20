use super::columns::NUM_LT_COLS;
use crate::{
    chips::{
        chips::{
            alu::{
                event::AluEvent,
                lt::{LtValueCols, NUM_LT_VALUE_COLS},
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
    machine::chip::ChipBehavior,
    primitives::consts::LT_DATAPAR,
};
use core::borrow::BorrowMut;
use itertools::izip;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use rayon::prelude::*;
use std::marker::PhantomData;
use tracing::debug;

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
            .par_chunks_mut(NUM_LT_VALUE_COLS)
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
            .par_chunks(chunk_size)
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
        debug!("{} chip - extra_record", self.name());
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
        let a = event.a.to_le_bytes();
        let b = event.b.to_le_bytes();
        let c = event.c.to_le_bytes();

        cols.a = Word(a.map(F::from_canonical_u8));
        cols.b = Word(b.map(F::from_canonical_u8));
        cols.c = Word(c.map(F::from_canonical_u8));

        // If this is SLT, mask the MSB of b & c before computing cols.bits.
        let masked_b = b[3] & 0x7f;
        let masked_c = c[3] & 0x7f;
        cols.b_masked = F::from_canonical_u8(masked_b);
        cols.c_masked = F::from_canonical_u8(masked_c);

        // Send the masked interaction.
        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::AND,
            a1: masked_b as u16,
            a2: 0,
            b: b[3],
            c: 0x7f,
        });
        blu.add_byte_lookup_event(ByteLookupEvent {
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
                *flag = F::ONE;
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
            F::ONE
        };

        cols.is_slt = F::from_bool(event.opcode == Opcode::SLT);
        cols.is_slt_u = F::from_bool(event.opcode == Opcode::SLTU);

        cols.bit_b = cols.msb_b * cols.is_slt;
        cols.bit_c = cols.msb_c * cols.is_slt;

        // when case msb_b = 0; msb_c = 1(negative), a0 = 0;
        // when case msb_b = 1(negative); msg_c = 0, a0 = 1;
        // when case msb_b and msb_c both is 0 or 1, a0 depends on SLTU.
        assert_eq!(
            cols.a[0],
            cols.msb_b * cols.is_slt * (F::ONE - cols.msb_c * cols.is_slt)
                + cols.is_sign_bit_same * cols.slt_u
        );

        blu.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: cols.slt_u.as_canonical_u32() as u16,
            a2: 0,
            b: cols.cmp_bytes[0].as_canonical_u32() as u8,
            c: cols.cmp_bytes[1].as_canonical_u32() as u8,
        });
    }
}
