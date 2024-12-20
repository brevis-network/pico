use super::{columns::NUM_DIVREM_COLS, DivRemChip};
use crate::{
    chips::{
        chips::{
            alu::{
                divrem::{
                    columns::DivRemCols,
                    utils::{get_msb, get_quotient_and_remainder, is_signed_operation},
                },
                event::AluEvent,
            },
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            rangecheck::event::RangeRecordBehavior,
        },
        utils::create_alu_lookups,
    },
    compiler::{
        riscv::{
            opcode::{ByteOpcode, Opcode},
            program::Program,
        },
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
    primitives::consts::{BYTE_SIZE, LONG_WORD_SIZE, WORD_SIZE},
};
use core::borrow::BorrowMut;
use hashbrown::HashMap;
use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

impl<F: Field> BaseAir<F> for DivRemChip<F> {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<F: Field> ChipBehavior<F> for DivRemChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "DivRem".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let mut rows: Vec<[F; NUM_DIVREM_COLS]> = vec![];
        let divrem_events = input.divrem_events.clone();
        for event in divrem_events.iter() {
            assert!(
                event.opcode == Opcode::DIVU
                    || event.opcode == Opcode::REMU
                    || event.opcode == Opcode::REM
                    || event.opcode == Opcode::DIV
            );
            let mut row = [F::ZERO; NUM_DIVREM_COLS];
            let cols: &mut DivRemCols<F> = row.as_mut_slice().borrow_mut();

            // Initialize cols with basic operands and flags derived from the current event.
            {
                cols.a = Word::from(event.a);
                cols.b = Word::from(event.b);
                cols.c = Word::from(event.c);
                cols.chunk = F::from_canonical_u32(event.chunk);
                cols.is_real = F::ONE;
                cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                cols.is_c_0.populate(event.c);
            }

            let (quotient, remainder) = get_quotient_and_remainder(event.b, event.c, event.opcode);
            cols.quotient = Word::from(quotient);
            cols.remainder = Word::from(remainder);

            // Calculate flags for sign detection.
            {
                cols.rem_msb = F::from_canonical_u8(get_msb(remainder));
                cols.b_msb = F::from_canonical_u8(get_msb(event.b));
                cols.c_msb = F::from_canonical_u8(get_msb(event.c));
                cols.is_overflow_b.populate(event.b, i32::MIN as u32);
                cols.is_overflow_c.populate(event.c, -1i32 as u32);
                if is_signed_operation(event.opcode) {
                    cols.rem_neg = cols.rem_msb;
                    cols.b_neg = cols.b_msb;
                    cols.c_neg = cols.c_msb;
                    cols.is_overflow =
                        F::from_bool(event.b as i32 == i32::MIN && event.c as i32 == -1);
                    cols.abs_remainder = Word::from((remainder as i32).unsigned_abs());
                    cols.abs_c = Word::from((event.c as i32).unsigned_abs());
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, (event.c as i32).unsigned_abs()));
                } else {
                    cols.abs_remainder = cols.remainder;
                    cols.abs_c = cols.c;
                    cols.max_abs_c_or_1 = Word::from(u32::max(1, event.c));
                }

                // Set the `alu_event` flags.
                cols.abs_c_alu_event = cols.c_neg * cols.is_real;
                cols.abs_c_alu_event_nonce = F::from_canonical_u32(
                    input
                        .nonce_lookup
                        .get(&event.sub_lookups[4])
                        .copied()
                        .unwrap_or_default(),
                );
                cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;
                cols.abs_rem_alu_event_nonce = F::from_canonical_u32(
                    input
                        .nonce_lookup
                        .get(&event.sub_lookups[5])
                        .copied()
                        .unwrap_or_default(),
                );

                // Insert the MSB lookup events.
                {
                    let words = [event.b, event.c, remainder];
                    let mut blu_events: Vec<ByteLookupEvent> = vec![];
                    for word in words.iter() {
                        let most_significant_byte = word.to_le_bytes()[WORD_SIZE - 1];
                        blu_events.push(ByteLookupEvent {
                            chunk: event.chunk,
                            opcode: ByteOpcode::MSB,
                            a1: get_msb(*word) as u16,
                            a2: 0,
                            b: most_significant_byte,
                            c: 0,
                        });
                    }
                    output.add_byte_lookup_events(blu_events);
                }
            }

            // Calculate the modified multiplicity
            {
                cols.remainder_check_multiplicity = cols.is_real * (F::ONE - cols.is_c_0.result);
            }

            // Calculate c * quotient + remainder.
            {
                let c_times_quotient = {
                    if is_signed_operation(event.opcode) {
                        (((quotient as i32) as i64) * ((event.c as i32) as i64)).to_le_bytes()
                    } else {
                        ((quotient as u64) * (event.c as u64)).to_le_bytes()
                    }
                };
                cols.c_times_quotient = c_times_quotient.map(F::from_canonical_u8);

                let remainder_bytes = {
                    if is_signed_operation(event.opcode) {
                        ((remainder as i32) as i64).to_le_bytes()
                    } else {
                        (remainder as u64).to_le_bytes()
                    }
                };

                // Add remainder to product.
                let mut carry = [0u32; 8];
                let base = 1 << BYTE_SIZE;
                for i in 0..LONG_WORD_SIZE {
                    let mut x = c_times_quotient[i] as u32 + remainder_bytes[i] as u32;
                    if i > 0 {
                        x += carry[i - 1];
                    }
                    carry[i] = x / base;
                    cols.carry[i] = F::from_canonical_u32(carry[i]);
                }

                // Insert the necessary multiplication & LT events.
                //
                // This generate_trace for div must be executed _before_ calling generate_trace for
                // mul and LT upon which div depends. This ordering is critical as mul and LT
                // require all the mul and LT events be added before we can call generate_trace.
                {
                    // Insert the absolute value computation events.
                    {
                        let mut add_events: Vec<AluEvent> = vec![];
                        if cols.abs_c_alu_event == F::ONE {
                            add_events.push(AluEvent {
                                lookup_id: event.sub_lookups[4],
                                chunk: event.chunk,
                                clk: event.clk,
                                opcode: Opcode::ADD,
                                a: 0,
                                b: event.c,
                                c: (event.c as i32).unsigned_abs(),
                                sub_lookups: create_alu_lookups(),
                            })
                        }
                        if cols.abs_rem_alu_event == F::ONE {
                            add_events.push(AluEvent {
                                lookup_id: event.sub_lookups[5],
                                chunk: event.chunk,
                                clk: event.clk,
                                opcode: Opcode::ADD,
                                a: 0,
                                b: remainder,
                                c: (remainder as i32).unsigned_abs(),
                                sub_lookups: create_alu_lookups(),
                            })
                        }
                        let mut alu_events = HashMap::new();
                        alu_events.insert(Opcode::ADD, add_events);
                        output.add_alu_events(alu_events);
                    }

                    let mut lower_word = 0;
                    for i in 0..WORD_SIZE {
                        lower_word += (c_times_quotient[i] as u32) << (i * BYTE_SIZE);
                    }

                    let mut upper_word = 0;
                    for i in 0..WORD_SIZE {
                        upper_word += (c_times_quotient[WORD_SIZE + i] as u32) << (i * BYTE_SIZE);
                    }

                    let lower_multiplication = AluEvent {
                        lookup_id: event.sub_lookups[0],
                        chunk: event.chunk,
                        clk: event.clk,
                        opcode: Opcode::MUL,
                        a: lower_word,
                        c: event.c,
                        b: quotient,
                        sub_lookups: create_alu_lookups(),
                    };
                    cols.lower_nonce = F::from_canonical_u32(
                        input
                            .nonce_lookup
                            .get(&event.sub_lookups[0])
                            .copied()
                            .unwrap_or_default(),
                    );
                    output.add_mul_event(lower_multiplication);

                    let upper_multiplication = AluEvent {
                        lookup_id: event.sub_lookups[1],
                        chunk: event.chunk,
                        clk: event.clk,
                        opcode: {
                            if is_signed_operation(event.opcode) {
                                Opcode::MULH
                            } else {
                                Opcode::MULHU
                            }
                        },
                        a: upper_word,
                        c: event.c,
                        b: quotient,
                        sub_lookups: create_alu_lookups(),
                    };
                    cols.upper_nonce = F::from_canonical_u32(
                        input
                            .nonce_lookup
                            .get(&event.sub_lookups[1])
                            .copied()
                            .unwrap_or_default(),
                    );
                    output.add_mul_event(upper_multiplication);
                    let lt_event = if is_signed_operation(event.opcode) {
                        cols.abs_nonce = F::from_canonical_u32(
                            input
                                .nonce_lookup
                                .get(&event.sub_lookups[2])
                                .copied()
                                .unwrap_or_default(),
                        );
                        AluEvent {
                            lookup_id: event.sub_lookups[2],
                            chunk: event.chunk,
                            opcode: Opcode::SLTU,
                            a: 1,
                            b: (remainder as i32).unsigned_abs(),
                            c: u32::max(1, (event.c as i32).unsigned_abs()),
                            clk: event.clk,
                            sub_lookups: create_alu_lookups(),
                        }
                    } else {
                        cols.abs_nonce = F::from_canonical_u32(
                            input
                                .nonce_lookup
                                .get(&event.sub_lookups[3])
                                .copied()
                                .unwrap_or_default(),
                        );
                        AluEvent {
                            lookup_id: event.sub_lookups[3],
                            chunk: event.chunk,
                            opcode: Opcode::SLTU,
                            a: 1,
                            b: remainder,
                            c: u32::max(1, event.c),
                            clk: event.clk,
                            sub_lookups: create_alu_lookups(),
                        }
                    };

                    if cols.remainder_check_multiplicity == F::ONE {
                        output.add_lt_event(lt_event);
                    }
                }

                // Range check.
                {
                    let chunk = event.chunk;
                    output.add_u8_range_checks(quotient.to_le_bytes(), Some(chunk));
                    output.add_u8_range_checks(remainder.to_le_bytes(), Some(chunk));
                    output.add_u8_range_checks(c_times_quotient, Some(chunk));
                }
            }

            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIVREM_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_DIVREM_COLS, F>(&mut trace.values);

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::ZERO; NUM_DIVREM_COLS];
            let cols: &mut DivRemCols<F> = row.as_mut_slice().borrow_mut();
            // 0 divided by 1. quotient = remainder = 0.
            cols.is_divu = F::ONE;
            cols.c[0] = F::ONE;
            cols.abs_c[0] = F::ONE;
            cols.max_abs_c_or_1[0] = F::ONE;

            cols.is_c_0.populate(1);

            row
        };
        debug_assert!(padded_row_template.len() == NUM_DIVREM_COLS);
        for i in input.divrem_events.len() * NUM_DIVREM_COLS..trace.values.len() {
            trace.values[i] = padded_row_template[i % NUM_DIVREM_COLS];
        }

        // Write the nonces to the trace.
        for i in 0..trace.height() {
            let cols: &mut DivRemCols<F> =
                trace.values[i * NUM_DIVREM_COLS..(i + 1) * NUM_DIVREM_COLS].borrow_mut();
            cols.nonce = F::from_canonical_usize(i);
        }

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.divrem_events.is_empty()
    }
}
