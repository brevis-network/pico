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
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::chip::ChipBehavior,
    recursion_v2::{air::IsZeroOperation, stark::utils::pad_rows_fixed},
};
use num::{BigUint, One, Zero};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
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
        let mut byte_lookup_events = vec![];

        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::UINT256_MUL)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::Uint256Mul(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        // Generate the trace rows & corresponding records for each event.
        let mut rows = events
            .iter()
            .map(|event| {
                let mut new_byte_lookup_events = vec![];

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
                        .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                    cols.y_memory[i]
                        .populate(event.y_memory_records[i], &mut new_byte_lookup_events);
                    cols.modulus_memory[i]
                        .populate(event.modulus_memory_records[i], &mut new_byte_lookup_events);
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
                    &mut new_byte_lookup_events,
                    &x,
                    &y,
                    &effective_modulus,
                    FieldOperation::Mul,
                );

                cols.modulus_is_not_zero = F::ONE - cols.modulus_is_zero.result;
                if cols.modulus_is_not_zero == F::ONE {
                    cols.output_range_check.populate(
                        &mut new_byte_lookup_events,
                        &result,
                        &effective_modulus,
                    );
                }

                byte_lookup_events.extend(new_byte_lookup_events);

                row
            })
            .collect();

        let log_rows = input.shape_chip_size(&self.name());
        println!("Log rows in uint256mul: {:?}", log_rows);

        pad_rows_fixed(
            &mut rows,
            || {
                let mut row: [F; NUM_UINT256_MUL_COLS] = [F::ZERO; NUM_UINT256_MUL_COLS];
                let cols: &mut Uint256MulCols<F> = row.as_mut_slice().borrow_mut();

                let x = BigUint::zero();
                let y = BigUint::zero();
                cols.output
                    .populate(&mut vec![], &x, &y, FieldOperation::Mul);

                row
            },
            log_rows,
        );

        output.add_byte_lookup_events(byte_lookup_events);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_UINT256_MUL_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        // !chunk.uint256_mul_events.is_empty()
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !chunk
                .get_precompile_events(SyscallCode::UINT256_MUL)
                .is_empty()
        }
    }
}
