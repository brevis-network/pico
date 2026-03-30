use super::{columns::NUM_DIVREM_COLS, DivRemChip};
use crate::{
    chips::{
        chips::{
            alu::{
                divrem::{
                    columns::{DivRemValueCols, NUM_DIVREM_VALUE_COLS},
                    utils::{
                        get_msb, get_quotient_and_remainder, is_signed_64bit_operation,
                        is_signed_operation, is_signed_word_operation, is_unsigned_64bit_operation,
                        is_unsigned_word_operation, is_word_operation,
                    },
                },
                event::AluEvent,
            },
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    iter::{PicoIterator, PicoSlice},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::{DIVREM_DATAPAR, LONG_WORD_SIZE},
};
use core::borrow::BorrowMut;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::num::Wrapping;

impl<F: Field> BaseAir<F> for DivRemChip<F> {
    fn width(&self) -> usize {
        NUM_DIVREM_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for DivRemChip<F> {
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
        let events = input.divrem_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(DIVREM_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_DIVREM_COLS];

        let populate_len = events.len() * NUM_DIVREM_VALUE_COLS;
        values[..populate_len]
            .chunks_mut(NUM_DIVREM_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut DivRemValueCols<_> = row.borrow_mut();

                // Get the correct computational values of `b`.
                let b = if is_signed_word_operation(event.opcode) {
                    event.b as i32 as i64 as u64
                } else if is_unsigned_word_operation(event.opcode) {
                    event.b as u32 as u64
                } else {
                    event.b
                };

                // Get the correct computational values of `c`.
                let c = if is_signed_word_operation(event.opcode) {
                    event.c as i32 as i64 as u64
                } else if is_unsigned_word_operation(event.opcode) {
                    event.c as u32 as u64
                } else {
                    event.c
                };

                // Initialize cols with basic operands and flags derived from the current event.
                {
                    cols.a = Word::from(event.a);
                    cols.b = Word::from(b);
                    cols.c = Word::from(c);

                    cols.is_real = F::ONE;

                    cols.is_divu = F::from_bool(event.opcode == Opcode::DIVU);
                    cols.is_remu = F::from_bool(event.opcode == Opcode::REMU);
                    cols.is_div = F::from_bool(event.opcode == Opcode::DIV);
                    cols.is_rem = F::from_bool(event.opcode == Opcode::REM);
                    cols.is_divw = F::from_bool(event.opcode == Opcode::DIVW);
                    cols.is_remw = F::from_bool(event.opcode == Opcode::REMW);
                    cols.is_divuw = F::from_bool(event.opcode == Opcode::DIVUW);
                    cols.is_remuw = F::from_bool(event.opcode == Opcode::REMUW);

                    let not_word_operation =
                        F::ONE - cols.is_divw - cols.is_remw - cols.is_divuw - cols.is_remuw;
                    cols.is_real_not_word = cols.is_real * not_word_operation;
                    cols.is_c_0.populate(c);
                }

                let (quotient, remainder) =
                    get_quotient_and_remainder(event.b, event.c, event.opcode);
                cols.quotient = Word::from(quotient);
                cols.remainder = Word::from(remainder);

                // Get the computational form of `quotient`.
                let quotient_comp = if is_unsigned_word_operation(event.opcode) {
                    quotient as u32 as u64
                } else {
                    quotient
                };
                cols.quotient_comp = Word::from(quotient_comp);

                let remainder_comp = if is_unsigned_word_operation(event.opcode) {
                    remainder as u32 as u64
                } else {
                    remainder
                };
                cols.remainder_comp = Word::from(remainder_comp);

                // Calculate flags for sign detection.
                {
                    if is_signed_64bit_operation(event.opcode) {
                        cols.rem_neg = F::from_canonical_u8(get_msb(remainder));
                        cols.b_neg = F::from_canonical_u8(get_msb(event.b));
                        cols.c_neg = F::from_canonical_u8(get_msb(event.c));
                        cols.is_overflow =
                            F::from_bool(event.b as i64 == i64::MIN && event.c as i64 == -1);
                        cols.abs_remainder = Word::from((remainder as i64).unsigned_abs());
                        cols.abs_c = Word::from((event.c as i64).unsigned_abs());
                        cols.max_abs_c_or_1 =
                            Word::from(u64::max(1, (event.c as i64).unsigned_abs()));
                    } else if is_signed_word_operation(event.opcode) {
                        cols.rem_neg =
                            F::from_canonical_u8(get_msb((remainder as i32) as i64 as u64));
                        cols.b_neg = F::from_canonical_u8(get_msb((event.b as i32) as i64 as u64));
                        cols.c_neg = F::from_canonical_u8(get_msb((event.c as i32) as i64 as u64));
                        cols.is_overflow =
                            F::from_bool(event.b as i32 == i32::MIN && event.c as i32 == -1);
                        cols.abs_remainder = Word::from((remainder as i64).unsigned_abs());
                        cols.abs_c = Word::from((c as i64).unsigned_abs());
                        cols.max_abs_c_or_1 = Word::from(u64::max(1, (c as i64).unsigned_abs()));
                    } else if is_unsigned_word_operation(event.opcode) {
                        cols.abs_remainder = cols.remainder_comp;
                        cols.abs_c = Word::from(event.c as u32);
                        cols.max_abs_c_or_1 = Word::from(u32::max(1, event.c as u32));
                    } else {
                        cols.abs_remainder = cols.remainder_comp;
                        cols.abs_c = Word::from(event.c);
                        cols.max_abs_c_or_1 = Word::from(u64::max(1, event.c));
                    }

                    if is_word_operation(event.opcode) {
                        cols.is_overflow_b
                            .populate((event.b as u32) as u64, i32::MIN as u32 as u64);
                        cols.is_overflow_c
                            .populate((event.c as u32) as u64, (-1i32 as u32) as u64);
                    } else {
                        cols.is_overflow_b.populate(event.b, i64::MIN as u64);
                        cols.is_overflow_c.populate(event.c, (-1i64) as u64);
                    }

                    cols.b_neg_not_overflow = cols.b_neg * (F::ONE - cols.is_overflow);
                    cols.b_not_neg_not_overflow =
                        (F::ONE - cols.b_neg) * (F::ONE - cols.is_overflow);

                    // Set the `alu_event` flags.
                    cols.abs_c_alu_event = cols.c_neg * cols.is_real;
                    cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;

                    output.add_u16_range_checks_field(&cols.abs_c.0);
                    output.add_u16_range_checks_field(&cols.abs_remainder.0);

                    // Populate the c_neg_operation and rem_neg_operation.
                    {
                        let mut blu_events = vec![];
                        if cols.abs_c_alu_event == F::ONE {
                            cols.c_neg_gadget.populate(
                                &mut blu_events,
                                cols.c.to_u64(),
                                cols.abs_c.to_u64(),
                            );
                        }
                        if cols.abs_rem_alu_event == F::ONE {
                            cols.rem_neg_gadget.populate(
                                &mut blu_events,
                                cols.remainder.to_u64(),
                                cols.abs_remainder.to_u64(),
                            );
                        }
                        output.add_byte_lookup_events(blu_events);
                    }

                    // Insert the MSB lookup events.
                    {
                        let mut blu_events: Vec<ByteLookupEvent> = vec![];

                        if is_word_operation(event.opcode) {
                            cols.b_msb.populate(&mut blu_events, (event.b >> 16) as u16);
                            cols.c_msb.populate(&mut blu_events, (event.c >> 16) as u16);
                            cols.rem_msb
                                .populate(&mut blu_events, (remainder >> 16) as u16);
                            cols.quot_msb
                                .populate(&mut blu_events, (quotient >> 16) as u16);
                        } else {
                            cols.b_msb.populate(&mut blu_events, (b >> 48) as u16);
                            cols.c_msb.populate(&mut blu_events, (c >> 48) as u16);
                            cols.rem_msb
                                .populate(&mut blu_events, (remainder >> 48) as u16);
                        }

                        output.add_byte_lookup_events(blu_events);
                    }
                }

                // Calculate the modified multiplicity
                {
                    let mut blu_events = vec![];
                    cols.remainder_check_multiplicity =
                        cols.is_real * (F::ONE - cols.is_c_0.result);
                    if cols.remainder_check_multiplicity == F::ONE {
                        cols.remainder_lt_gadget.populate(
                            &mut blu_events,
                            1,
                            cols.abs_remainder.to_u64(),
                            cols.max_abs_c_or_1.to_u64(),
                        );
                    }

                    output.add_byte_lookup_events(blu_events);
                }

                // Calculate c * quotient + remainder.
                {
                    let mut blu_events = vec![];
                    let mut c_times_quotient_byte = [0u8; 16];

                    let c_times_quotient_byte_lower =
                        ((Wrapping(quotient_comp) * Wrapping(c)).0 as u64).to_le_bytes();

                    let c_times_quotient_byte_upper = if is_signed_64bit_operation(event.opcode)
                        || is_signed_word_operation(event.opcode)
                    {
                        ((((quotient_comp as i64) as i128).wrapping_mul((c as i64) as i128) >> 64)
                            as u64)
                            .to_le_bytes()
                    } else {
                        (((quotient_comp as u128 * c as u128) >> 64) as u64).to_le_bytes()
                    };

                    c_times_quotient_byte[..8].copy_from_slice(&c_times_quotient_byte_lower);
                    c_times_quotient_byte[8..].copy_from_slice(&c_times_quotient_byte_upper);

                    let c_times_quotient_u16: [u16; LONG_WORD_SIZE] = core::array::from_fn(|i| {
                        u16::from_le_bytes([
                            c_times_quotient_byte[2 * i],
                            c_times_quotient_byte[2 * i + 1],
                        ])
                    });

                    cols.c_times_quotient = c_times_quotient_u16.map(F::from_canonical_u16);

                    cols.c_times_quotient_lower.populate(
                        &mut blu_events,
                        quotient_comp,
                        c,
                        false,
                        false,
                        false,
                    );

                    if is_signed_64bit_operation(event.opcode) {
                        cols.c_times_quotient_upper.populate(
                            &mut blu_events,
                            quotient_comp,
                            c,
                            true,  // is_mulh - true for DIV/REM (signed)
                            false, // is_mulhsu
                            false, // is_mulw
                        );
                    }
                    if is_unsigned_64bit_operation(event.opcode) {
                        cols.c_times_quotient_upper.populate(
                            &mut blu_events,
                            quotient_comp,
                            c,
                            false, // is_mulh
                            false, // is_mulhsu
                            false, // is_mulw
                        );
                    }

                    output.add_byte_lookup_events(blu_events);

                    // Create remainder_u16 with sign extension based on rem_neg
                    let mut remainder_u16 = [0u32; 8];
                    for i in 0..4 {
                        remainder_u16[i] = cols.remainder_comp[i].as_canonical_u32();
                        remainder_u16[i + 4] = cols.rem_neg.as_canonical_u32() * ((1 << 16) - 1);
                    }

                    // Add remainder to product.
                    let mut carry = [0u32; 8];
                    let base = 1 << 16;
                    for i in 0..LONG_WORD_SIZE {
                        let mut x = c_times_quotient_u16[i] as u32 + remainder_u16[i];
                        if i > 0 {
                            x += carry[i - 1];
                        }
                        carry[i] = x / base;
                        cols.carry[i] = F::from_canonical_u32(carry[i]);
                        output.add_u16_range_check((x & 0xFFFF) as u16);
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
                                    clk: event.clk,
                                    opcode: Opcode::ADD,
                                    a: 0,
                                    b: c,
                                    c: cols.abs_c.to_u64(),
                                    ..Default::default()
                                })
                            }
                            if cols.abs_rem_alu_event == F::ONE {
                                add_events.push(AluEvent {
                                    clk: event.clk,
                                    opcode: Opcode::ADD,
                                    a: 0,
                                    b: remainder,
                                    c: cols.abs_remainder.to_u64(),
                                    ..Default::default()
                                })
                            }
                            let mut alu_events = HashMap::new();
                            alu_events.insert(Opcode::ADD, add_events);
                            output.add_alu_events(alu_events);
                        }
                    }

                    // Range check.
                    {
                        output.add_u16_range_checks(&[
                            (quotient & 0xFFFF) as u16,
                            (quotient >> 16) as u16,
                            (quotient >> 32) as u16,
                            (quotient >> 48) as u16,
                        ]);
                        output.add_u16_range_checks(&[
                            (remainder & 0xFFFF) as u16,
                            (remainder >> 16) as u16,
                            (remainder >> 32) as u16,
                            (remainder >> 48) as u16,
                        ]);
                        output.add_u16_range_checks(&c_times_quotient_u16);
                    }
                }
            });

        // Create the template for the padded rows. These are fake rows that don't fail on some
        // sanity checks.
        let padded_row_template = {
            let mut row = [F::ZERO; NUM_DIVREM_VALUE_COLS];
            let cols: &mut DivRemValueCols<F> = row.as_mut_slice().borrow_mut();
            // 0 divided by 1. quotient = remainder = 0.
            cols.is_divu = F::ONE;
            cols.c[0] = F::ONE;
            cols.abs_c[0] = F::ONE;
            cols.max_abs_c_or_1[0] = F::ONE;
            cols.b_not_neg_not_overflow = F::ONE;

            cols.is_c_0.populate(1);

            row
        };

        for i in populate_len..values.len() {
            values[i] = padded_row_template[i % NUM_DIVREM_VALUE_COLS];
        }

        RowMajorMatrix::new(values, NUM_DIVREM_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.divrem_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F> EventCapture for DivRemChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_divrem_events += record.divrem_events.len();
        if event_counter.num_divrem_events == 0 {
            return;
        }

        event_counter.num_mul_events += 2 * record.divrem_events.len();
        let chunk_size = std::cmp::max(record.divrem_events.len() / num_cpus::get(), 1);
        let divrem_counts: Vec<(usize, usize)> = record
            .divrem_events
            .as_slice()
            .pico_chunks(chunk_size)
            .flat_map_iter(|chunk| chunk.iter().map(|e| Self::count_event(e)))
            .collect();
        let (divrem_add, divrem_lt) = divrem_counts
            .as_slice()
            .pico_chunks(chunk_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold((0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1))
            })
            .pico_reduce(|| (0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1));
        event_counter.num_add_events += divrem_add;
        event_counter.num_lt_events += divrem_lt;
    }
}

impl<F> DivRemChip<F> {
    fn count_event(event: &AluEvent) -> (usize, usize) {
        let mut add_events = 0;
        let mut lt_events = 0;
        let is_real = 1;
        let mut c_neg = 0;
        let b = event.b;
        let c = event.c;
        let (_, remainder) = get_quotient_and_remainder(b, c, event.opcode);
        let mut rem_neg = 0;
        if is_signed_operation(event.opcode) {
            c_neg = get_msb(c);
            rem_neg = get_msb(remainder);
        }
        let abs_c_alu_event = c_neg * is_real;
        if abs_c_alu_event == 1 {
            add_events += 1;
        }

        let abs_rem_alu_event = rem_neg * is_real;
        if abs_rem_alu_event == 1 {
            add_events += 1;
        }
        let is_c_0 = c == 0;
        let remainder_check_multiplicity = is_real * (1 - (is_c_0 as u8));
        if remainder_check_multiplicity == 1 {
            lt_events += 1;
        }

        (add_events, lt_events)
    }
}
