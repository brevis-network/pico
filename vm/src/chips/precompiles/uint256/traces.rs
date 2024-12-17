use super::columns::{Uint256MulCols, NUM_UINT256_MUL_COLS};
use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{
            field::field_op::FieldOperation,
            utils::conversions::{words_to_bytes_le, words_to_bytes_le_vec},
        },
        precompiles::uint256::{Uint256MulChip, UINT256_NUM_WORDS},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
    recursion_v2::{air::IsZeroOperation, stark::utils::pad_rows_fixed},
};
use hashbrown::HashMap;
use num::{BigUint, One, Zero};
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for Uint256MulChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Uint256MulMod".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        // The record update is used by extra_record
        let mut chunked_byte_lookup_events = Vec::new();
        let mut rangecheck_lookup_events = Vec::new();
        // Generate the trace rows & corresponding records for each event.
        let mut rows = input
            .uint256_mul_events
            .iter()
            .map(|event| {
                let mut new_range_check_events = HashMap::new();
                let mut new_byte_lookup_events = HashMap::new();

                let mut row: [F; NUM_UINT256_MUL_COLS] = [F::ZERO; NUM_UINT256_MUL_COLS];
                let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

                // Decode uint256 points
                let x = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.x));
                let y = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.y));
                let modulus = BigUint::from_bytes_le(&words_to_bytes_le::<32>(&event.modulus));

                // Assign basic values to the columns.
                cols.is_real = F::ONE;
                cols.chunk = F::from_canonical_u32(event.chunk);
                cols.clk = F::from_canonical_u32(event.clk);
                cols.x_ptr = F::from_canonical_u32(event.x_ptr);
                cols.y_ptr = F::from_canonical_u32(event.y_ptr);

                // Populate memory columns.
                for i in 0..UINT256_NUM_WORDS {
                    cols.x_memory[i]
                        .populate(event.x_memory_records[i], &mut new_range_check_events);
                    cols.y_memory[i]
                        .populate(event.y_memory_records[i], &mut new_range_check_events);
                    cols.modulus_memory[i]
                        .populate(event.modulus_memory_records[i], &mut new_range_check_events);
                }

                let modulus_bytes = words_to_bytes_le_vec(&event.modulus);
                let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u32).sum::<u32>();
                IsZeroOperation::populate(
                    &mut cols.modulus_is_zero,
                    F::from_canonical_u32(modulus_byte_sum),
                );

                // Populate the output column.
                let effective_modulus = if modulus.is_zero() {
                    BigUint::one() << 256
                } else {
                    modulus.clone()
                };
                let result = cols.output.populate_with_modulus(
                    &mut new_range_check_events,
                    event.chunk,
                    &x,
                    &y,
                    &effective_modulus,
                    FieldOperation::Mul,
                );

                cols.modulus_is_not_zero = F::ONE - cols.modulus_is_zero.result;
                if cols.modulus_is_not_zero == F::ONE {
                    cols.output_range_check.populate(
                        &mut new_byte_lookup_events,
                        event.chunk,
                        &result,
                        &effective_modulus,
                    );
                }

                chunked_byte_lookup_events.push(new_byte_lookup_events);
                rangecheck_lookup_events.push(new_range_check_events);
                row
            })
            .collect::<Vec<_>>();

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_UINT256_MUL_COLS] = [F::ZERO; NUM_UINT256_MUL_COLS];
                let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

                let x = BigUint::zero();
                let y = BigUint::zero();
                cols.output
                    .populate(&mut vec![], 0, &x, &y, FieldOperation::Mul);

                row
            },
            None,
        );

        output.add_chunked_byte_lookup_events(chunked_byte_lookup_events.iter().collect());
        output.add_rangecheck_lookup_events(rangecheck_lookup_events);

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UINT256_MUL_COLS,
        );

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut Uint256MulCols<F> =
                trace.values[i * NUM_UINT256_MUL_COLS..(i + 1) * NUM_UINT256_MUL_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        !chunk.uint256_mul_events.is_empty()
    }
}
