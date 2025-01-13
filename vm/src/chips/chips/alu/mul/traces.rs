use super::{columns::NUM_MUL_COLS, MulChip};
use crate::{
    chips::{
        chips::{
            alu::mul::{columns::MulCols, BYTE_MASK, PRODUCT_SIZE},
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            rangecheck::event::RangeRecordBehavior,
        },
        utils::get_msb,
    },
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            program::Program,
        },
        word::Word,
    },
    emulator::{record::RecordBehavior, riscv::record::EmulationRecord},
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
    primitives::consts::{BYTE_SIZE, WORD_SIZE},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use rayon::{iter::ParallelIterator, slice::ParallelSlice};
use std::borrow::BorrowMut;

impl<F: Field> BaseAir<F> for MulChip<F> {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<F: PrimeField> ChipBehavior<F> for MulChip<F> {
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
        let mul_events = input.mul_events.clone();
        // Compute the chunk size based on the number of events and the number of CPUs.
        let chunk_size = std::cmp::max(mul_events.len() / num_cpus::get(), 1);

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows_and_records = mul_events
            .par_chunks(chunk_size)
            .map(|events| {
                let mut record = EmulationRecord::default();
                let rows = events
                    .iter()
                    .map(|event| {
                        // Ensure that the opcode is MUL, MULHU, MULH, or MULHSU.
                        assert!(
                            event.opcode == Opcode::MUL
                                || event.opcode == Opcode::MULHU
                                || event.opcode == Opcode::MULH
                                || event.opcode == Opcode::MULHSU
                        );
                        let mut row = [F::ZERO; NUM_MUL_COLS];
                        let cols: &mut MulCols<F> = row.as_mut_slice().borrow_mut();

                        let a_word = event.a.to_le_bytes();
                        let b_word = event.b.to_le_bytes();
                        let c_word = event.c.to_le_bytes();

                        let mut b = b_word.to_vec();
                        let mut c = c_word.to_vec();

                        // Handle b and c's signs.
                        {
                            let b_msb = get_msb(b_word);
                            cols.b_msb = F::from_canonical_u8(b_msb);
                            let c_msb = get_msb(c_word);
                            cols.c_msb = F::from_canonical_u8(c_msb);

                            // If b is signed and it is negative, sign extend b.
                            if (event.opcode == Opcode::MULH || event.opcode == Opcode::MULHSU)
                                && b_msb == 1
                            {
                                cols.b_sign_extend = F::ONE;
                                b.resize(PRODUCT_SIZE, BYTE_MASK);
                            }

                            // If c is signed and it is negative, sign extend c.
                            if event.opcode == Opcode::MULH && c_msb == 1 {
                                cols.c_sign_extend = F::ONE;
                                c.resize(PRODUCT_SIZE, BYTE_MASK);
                            }

                            // Insert the MSB lookup events.
                            {
                                let words = [b_word, c_word];
                                let mut blu_events: Vec<ByteLookupEvent> = vec![];
                                for word in words.iter() {
                                    let most_significant_byte = word[WORD_SIZE - 1];
                                    blu_events.push(ByteLookupEvent {
                                        chunk: event.chunk,
                                        opcode: ByteOpcode::MSB,
                                        a1: get_msb(*word) as u16,
                                        a2: 0,
                                        b: most_significant_byte,
                                        c: 0,
                                    });
                                }
                                record.add_byte_lookup_events(blu_events);
                            }
                        }

                        let mut product = [0u32; PRODUCT_SIZE];
                        for i in 0..b.len() {
                            for j in 0..c.len() {
                                if i + j < PRODUCT_SIZE {
                                    product[i + j] += (b[i] as u32) * (c[j] as u32);
                                }
                            }
                        }

                        // Calculate the correct product using the `product` array. We store the
                        // correct carry value for verification.
                        let base = (1 << BYTE_SIZE) as u32;
                        let mut carry = [0u32; PRODUCT_SIZE];
                        for i in 0..PRODUCT_SIZE {
                            carry[i] = product[i] / base;
                            product[i] %= base;
                            if i + 1 < PRODUCT_SIZE {
                                product[i + 1] += carry[i];
                            }
                            cols.carry[i] = F::from_canonical_u32(carry[i]);
                        }

                        cols.product = product.map(F::from_canonical_u32);
                        cols.a = Word(a_word.map(F::from_canonical_u8));
                        cols.b = Word(b_word.map(F::from_canonical_u8));
                        cols.c = Word(c_word.map(F::from_canonical_u8));
                        cols.is_real = F::ONE;
                        cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
                        cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH);
                        cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU);
                        cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU);
                        cols.chunk = F::from_canonical_u32(event.chunk);

                        // Range check.
                        {
                            let chunk = event.chunk;
                            record.add_u16_range_checks(&carry.map(|x| x as u16), Some(chunk));
                            record.add_u8_range_checks(product.map(|x| x as u8), Some(chunk));
                        }

                        row
                    })
                    .collect::<Vec<_>>();
                (rows, record)
            })
            .collect::<Vec<_>>();

        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_MUL_COLS]> = vec![];
        for mut row_and_record in rows_and_records {
            rows.extend(row_and_record.0);
            output.append(&mut row_and_record.1);
        }

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_MUL_COLS);

        // Pad the trace based on shape
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_MUL_COLS, F>(&mut trace.values, log_rows);

        trace
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
