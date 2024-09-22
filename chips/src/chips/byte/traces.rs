use hashbrown::HashMap;
use itertools::Itertools;
use log::info;
use std::borrow::BorrowMut;

use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use pico_compiler::{opcode::ByteOpcode, program::Program};
use pico_emulator::riscv::record::EmulationRecord;
use pico_machine::chip::ChipBehavior;

use super::{
    columns::{ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    utils::shr_carry,
    ByteChip,
};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: Field> ChipBehavior<F> for ByteChip<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, _program: &Program) -> Option<RowMajorMatrix<F>> {
        info!("ByteChip - generate_preprocessed: BEGIN");
        let trace: p3_matrix::dense::DenseMatrix<F> = Self::preprocess();
        info!("ByteChip - generate_preprocessed: END");
        Some(trace)
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        info!("ByteChip - generate_main: BEGIN");
        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_BYTE_MULT_COLS * NUM_ROWS],
            NUM_BYTE_MULT_COLS,
        );
        // TODO: We always have one shard for now, and the shard number starts from 1.
        let shard = 1;
        for (lookup, mult) in input
            .byte_lookups
            .get(&shard)
            .unwrap_or(&HashMap::new())
            .iter()
        {
            let row = if lookup.opcode != ByteOpcode::U16Range {
                (((lookup.b as u16) << 8) + lookup.c as u16) as usize
            } else {
                lookup.a1 as usize
            };
            let index = lookup.opcode as usize;
            let channel = lookup.channel as usize;

            let cols: &mut ByteMultCols<F> = trace.row_mut(row).borrow_mut();
            cols.mult_channels[channel].multiplicities[index] += F::from_canonical_usize(*mult);
            cols.shard = F::from_canonical_u32(shard);
        }

        info!("ByteChip - generate_main: END");
        trace
    }
}

impl<F: Field> ByteChip<F> {
    /// Creates the preprocessed byte trace.
    ///
    /// This function returns a `trace` which is a matrix containing all possible byte operations.
    pub fn preprocess() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_ROWS * NUM_BYTE_PREPROCESSED_COLS],
            NUM_BYTE_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
            let b = b as u8;
            let c = c as u8;
            let col: &mut BytePreprocessedCols<F> = initial_trace.row_mut(row_index).borrow_mut();

            // Set the values of `b` and `c`.
            col.b = F::from_canonical_u8(b);
            col.c = F::from_canonical_u8(c);

            // Iterate over all operations for results and updating the table map.
            for opcode in opcodes.iter() {
                match opcode {
                    ByteOpcode::AND => {
                        let and = b & c;
                        col.and = F::from_canonical_u8(and);
                    }
                    ByteOpcode::OR => {
                        let or = b | c;
                        col.or = F::from_canonical_u8(or);
                    }
                    ByteOpcode::XOR => {
                        let xor = b ^ c;
                        col.xor = F::from_canonical_u8(xor);
                    }
                    ByteOpcode::SLL => {
                        let sll = b << (c & 7);
                        col.sll = F::from_canonical_u8(sll);
                    }
                    ByteOpcode::U8Range => {}
                    ByteOpcode::ShrCarry => {
                        let (res, carry) = shr_carry(b, c);
                        col.shr = F::from_canonical_u8(res);
                        col.shr_carry = F::from_canonical_u8(carry);
                    }
                    ByteOpcode::LTU => {
                        let ltu = b < c;
                        col.ltu = F::from_bool(ltu);
                    }
                    ByteOpcode::MSB => {
                        let msb = (b & 0b1000_0000) != 0;
                        col.msb = F::from_bool(msb);
                    }
                    ByteOpcode::U16Range => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_canonical_u32(v);
                    }
                };
            }
        }
        initial_trace
    }
}
