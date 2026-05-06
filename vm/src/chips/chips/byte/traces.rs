use super::{
    columns::{ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS},
    utils::shr_carry,
    ByteChip,
};
use crate::{
    compiler::riscv::{opcode::ByteOpcode, program::Program},
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
};
use itertools::Itertools;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use std::borrow::BorrowMut;

pub const NUM_ROWS: usize = 1 << 17;

impl<F: PrimeField32> ChipBehavior<F> for ByteChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Byte".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BYTE_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, _program: &Program) -> Option<RowMajorMatrix<F>> {
        let trace = Self::preprocess();
        Some(trace)
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let mut values = vec![F::ZERO; NUM_BYTE_MULT_COLS * NUM_ROWS];

        // Convert HashMap entries to Vec for parallel iteration
        let lookups: Vec<_> = input.byte_lookups.iter().collect();

        values
            .par_chunks_mut(NUM_BYTE_MULT_COLS)
            .enumerate()
            .for_each(|(row_idx, row)| {
                for (lookup, mult) in lookups.iter() {
                    let row_index: usize =
                        if lookup.opcode == ByteOpcode::BitRange && lookup.a2 == 16 {
                            // U16Range: row = (b << 8) | c
                            ((lookup.b as usize) << 8) + lookup.c as usize
                        } else if lookup.opcode == ByteOpcode::BitRange && lookup.a2 < 16 {
                            // BitRange: row = 65536 + (b << 8) | c + (1 << bits)
                            let base = 1usize << 16;
                            base + ((lookup.b as usize) << 8)
                                + lookup.c as usize
                                + (1usize << lookup.a2 as usize)
                        } else {
                            // Other byte ops: row = (b << 8) | c
                            ((lookup.b as usize) << 8) + lookup.c as usize
                        };

                    if row_idx == row_index {
                        let cols: &mut ByteMultCols<F> = row.borrow_mut();
                        let index = lookup.opcode as usize;
                        cols.multiplicities[index] += F::from_canonical_usize(**mult);
                    }
                }
            });

        RowMajorMatrix::new(values, NUM_BYTE_MULT_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<F: Field> ByteChip<F> {
    /// Creates the preprocessed byte trace.
    ///
    /// This function returns a `trace` which is a matrix containing all possible byte operations.
    pub fn preprocess() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_ROWS * NUM_BYTE_PREPROCESSED_COLS],
            NUM_BYTE_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each byte lookup.
        let opcodes = ByteOpcode::all();

        // Iterate over all options for pairs of bytes `a` and `b`.
        for (row_index, (b, c)) in (0..=u8::MAX).cartesian_product(0..=u8::MAX).enumerate() {
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
                    ByteOpcode::U8Range => (),
                    ByteOpcode::U16Range => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_canonical_u32(v);
                    }
                    ByteOpcode::BitRange => {
                        let v = ((b as u32) << 8) + c as u32;
                        col.value_u16 = F::from_canonical_u32(v);
                        col.bits = F::from_canonical_u8(16);
                    }
                };
            }
        }

        // Fill BitRange table for bits = 0..16
        // Rows 65536..131071: bits = 0..15 (bits=16 already filled in first 65536 rows)
        let base_row = 1 << 16;
        for bits in 0..16u8 {
            for a in 0..(1u16 << bits) {
                let row_index = base_row + a as usize + (1usize << bits);
                if row_index < NUM_ROWS {
                    let col: &mut BytePreprocessedCols<F> =
                        initial_trace.row_mut(row_index).borrow_mut();
                    col.value_u16 = F::from_canonical_u16(a);
                    col.bits = F::from_canonical_u8(bits);
                }
            }
        }
        initial_trace
    }
}
