use super::columns::{Uint256MulCols, NUM_UINT256_MUL_COLS};
use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        gadgets::{field::field_op::FieldOperation, is_zero::IsZeroGadget},
        precompiles::{
            checked_u64_to_u32,
            uint256::{Uint256MulChip, UINT256_NUM_WORDS},
        },
        utils::pad_rows_fixed,
    },
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::chip::ChipBehavior,
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

                // Decode uint256 values directly from native dword arrays.
                let x = BigUint::from_bytes_le(
                    &event
                        .x
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let y = BigUint::from_bytes_le(
                    &event
                        .y
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );
                let modulus = BigUint::from_bytes_le(
                    &event
                        .modulus
                        .iter()
                        .flat_map(|w| w.to_le_bytes())
                        .collect::<Vec<u8>>(),
                );

                // Assign basic values to the columns.
                cols.is_real = F::ONE;

                cols.chunk = F::from_canonical_u32(event.chunk);
                cols.clk = F::from_canonical_u32(checked_u64_to_u32(event.clk, "uint256 clk"));

                // Populate pointer gadgets.
                cols.x_ptr
                    .populate(&mut new_byte_lookup_events, event.x_ptr, 32);
                cols.y_ptr
                    .populate(&mut new_byte_lookup_events, event.y_ptr, 64);

                // Populate memory columns with native dword records.
                for i in 0..UINT256_NUM_WORDS {
                    cols.x_memory[i]
                        .inner
                        .populate(event.x_memory_records[i], &mut new_byte_lookup_events);
                    cols.x_memory[i].prev_value_u8.populate_u16_to_u8_safe(
                        &mut new_byte_lookup_events,
                        event.x_memory_records[i].prev_value,
                    );
                    cols.x_addrs[i].populate(
                        &mut new_byte_lookup_events,
                        event.x_ptr,
                        8 * i as u64,
                    );

                    cols.y_memory[i]
                        .inner
                        .populate(event.y_memory_records[i], &mut new_byte_lookup_events);
                    cols.y_memory[i].prev_value_u8.populate_u16_to_u8_safe(
                        &mut new_byte_lookup_events,
                        event.y_memory_records[i].value,
                    );
                    cols.y_and_modulus_addrs[i].populate(
                        &mut new_byte_lookup_events,
                        event.y_ptr,
                        8 * i as u64,
                    );

                    cols.modulus_memory[i]
                        .inner
                        .populate(event.modulus_memory_records[i], &mut new_byte_lookup_events);
                    cols.modulus_memory[i]
                        .prev_value_u8
                        .populate_u16_to_u8_safe(
                            &mut new_byte_lookup_events,
                            event.modulus_memory_records[i].value,
                        );
                    cols.y_and_modulus_addrs[UINT256_NUM_WORDS + i].populate(
                        &mut new_byte_lookup_events,
                        event.y_ptr,
                        8 * (UINT256_NUM_WORDS + i) as u64,
                    );
                }

                // Compute modulus_is_zero from modulus bytes.
                let modulus_bytes: Vec<u8> =
                    event.modulus.iter().flat_map(|w| w.to_le_bytes()).collect();
                let modulus_byte_sum = modulus_bytes.iter().map(|b| *b as u32).sum::<u32>();
                IsZeroGadget::populate(&mut cols.modulus_is_zero, modulus_byte_sum);

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
