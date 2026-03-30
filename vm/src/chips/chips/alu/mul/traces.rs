use super::{columns::NUM_MUL_COLS, MulChip};
use crate::{
    chips::{
        chips::alu::mul::columns::{MulValueCols, NUM_MUL_VALUE_COLS},
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::{record::RecordBehavior, riscv::record::EmulationRecord},
    machine::chip::ChipBehavior,
    primitives::consts::MUL_DATAPAR,
};
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: Field> BaseAir<F> for MulChip<F> {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for MulChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Mul".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.mul_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(MUL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_MUL_COLS];

        let populate_len = events.len() * NUM_MUL_VALUE_COLS;
        let mut record = EmulationRecord::default();

        values[..populate_len]
            .chunks_mut(NUM_MUL_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut MulValueCols<_> = row.borrow_mut();
                // Ensure that the opcode is MUL, MULHU, MULH, MULHSU, or MULW.
                assert!(
                    event.opcode == Opcode::MUL
                        || event.opcode == Opcode::MULHU
                        || event.opcode == Opcode::MULH
                        || event.opcode == Opcode::MULHSU
                        || event.opcode == Opcode::MULW
                );

                // Set the output operand a
                cols.a = Word::from(event.a);

                // Use MulGadget to populate the multiplication columns
                let is_mulh = event.opcode == Opcode::MULH;
                let is_mulhsu = event.opcode == Opcode::MULHSU;
                let is_mulw = event.opcode == Opcode::MULW;
                cols.mul_gadget.populate(
                    &mut record,
                    event.b,
                    event.c,
                    is_mulh,
                    is_mulhsu,
                    is_mulw,
                );

                // Set the input operands b and c
                cols.b = Word::from(event.b);
                cols.c = Word::from(event.c);

                // Set opcode flags
                cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
                cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH);
                cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU);
                cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU);
                cols.is_mulw = F::from_bool(event.opcode == Opcode::MULW);
            });

        output.append(&mut record);
        RowMajorMatrix::new(values, NUM_MUL_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.mul_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}
