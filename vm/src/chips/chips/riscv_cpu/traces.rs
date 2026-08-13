use super::{
    columns::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS},
    CpuChip,
};
use crate::{
    chips::chips::{
        alu::event::AluEvent,
        byte::event::ByteRecordBehavior,
        riscv_cpu::event::CpuEvent,
        riscv_memory::{event::MemoryRecordEnum, read_write::columns::MemoryCols},
    },
    compiler::{
        addr::Addr,
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::EmulationRecord,
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    iter::{IntoPicoRefMutIterator, PicoBridge, PicoIterator, PicoSlice},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
};
use hashbrown::HashMap;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: Field> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F: PrimeField32> ChipBehavior<F> for CpuChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    /// This name is now hard-coded and is related to MachineBehavior
    fn name(&self) -> String {
        "Cpu".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let mut values = vec![F::ZERO; input.cpu_events.len() * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_CPU_COLS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuCols<F> = row.borrow_mut();
                        let mut byte_lookup_events = Vec::new();
                        self.event_to_row(&input.cpu_events[idx], cols, &mut byte_lookup_events);
                    });
            });

        // Post-processing: compute pc_carry_a from adjacent rows.
        // carry_a is for cross-row constraints (pc+4 = next_row.pc), which needs
        // the actual next row's pc value, not available during per-row event_to_row.
        let n_events = input.cpu_events.len();
        if n_events > 1 {
            let rows_slice = unsafe {
                core::slice::from_raw_parts_mut(
                    values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                    n_events,
                )
            };
            for i in 0..n_events - 1 {
                let cur: &CpuCols<F> = unsafe { &*(rows_slice[i].as_ptr() as *const CpuCols<F>) };
                let next_row: &CpuCols<F> =
                    unsafe { &*(rows_slice[i + 1].as_ptr() as *const CpuCols<F>) };

                // carry_a is only needed when is_sequential or not_branching
                let is_seq = cur.is_sequential_instr == F::ONE;
                let not_branch = cur.not_branching == F::ONE;
                if is_seq || not_branch {
                    let base: u64 = 1 << 16;
                    let pc_limbs = [
                        cur.pc[0].as_canonical_u32() as u64,
                        cur.pc[1].as_canonical_u32() as u64,
                        cur.pc[2].as_canonical_u32() as u64,
                    ];
                    let next_pc_limbs = [
                        next_row.pc[0].as_canonical_u32() as u64,
                        next_row.pc[1].as_canonical_u32() as u64,
                        next_row.pc[2].as_canonical_u32() as u64,
                    ];
                    let mut carry: u64 = 0;
                    let cur_mut: &mut CpuCols<F> =
                        unsafe { &mut *(rows_slice[i].as_mut_ptr() as *mut CpuCols<F>) };
                    for k in 0..4 {
                        let lhs = if k < 3 { pc_limbs[k] } else { 0 };
                        let rhs = if k < 3 { next_pc_limbs[k] } else { 0 };
                        let inc = if k == 0 { 4u64 } else { 0 };
                        carry = (carry + lhs + inc - rhs) / base;
                        cur_mut.pc_carry_a[k] = F::from_canonical_u64(carry);
                    }
                }
            }
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two(self, input.shape.as_ref(), &mut trace.values);

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let (alu_events, blu_events): (Vec<_>, Vec<_>) = input
            .cpu_events
            .pico_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                let mut alu = HashMap::new();
                // The range map stores range (u8) lookup event -> multiplicity.
                let mut blu = vec![];
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let alu_events = self.event_to_row(op, cols, &mut blu);
                    alu_events.into_iter().for_each(|(key, value)| {
                        alu.entry(key).or_insert(Vec::default()).extend(value);
                    });
                });
                (alu, blu)
            })
            .unzip();
        for alu_events_chunk in alu_events {
            extra.add_alu_events(alu_events_chunk);
        }
        for blu_events_chunk in blu_events {
            extra.add_byte_lookup_events(blu_events_chunk);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.cpu_events.is_empty()
    }
}

impl<F> EventCapture for CpuChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_cpu_events += record.cpu_events.len();
        if event_counter.num_cpu_events == 0 {
            return;
        }

        let chunk_size = std::cmp::max(event_counter.num_cpu_events / num_cpus::get(), 1);
        let cpu_counts: Vec<(usize, usize)> = record
            .cpu_events
            .as_slice()
            .pico_chunks(chunk_size)
            .flat_map_iter(|chunk| chunk.iter().map(|e| Self::count_cpu_event(e)))
            .collect();
        let (cpu_add, cpu_lt) = cpu_counts
            .as_slice()
            .pico_chunks(chunk_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold((0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1))
            })
            .pico_reduce(|| (0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1));
        event_counter.num_add_events += cpu_add;
        event_counter.num_lt_events += cpu_lt;
    }
}

impl<F> CpuChip<F> {
    fn count_cpu_event(event: &CpuEvent) -> (usize, usize) {
        let mut add_events = 0;
        let mut lt_events = 0;

        if event.instruction.is_branch_instruction() {
            lt_events += 2;

            let a = event.a;
            let b = event.b;
            let a_eq_b = a == b;
            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);
            let a_lt_b = if use_signed_comparison {
                (a as i64) < (b as i64)
            } else {
                a < b
            };
            let a_gt_b = if use_signed_comparison {
                (a as i64) > (b as i64)
            } else {
                a > b
            };
            let branching = match event.instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
                _ => unreachable!(),
            };
            if branching {
                add_events += 1;
            }
        }
        if event.instruction.is_jump_instruction() {
            add_events += 1;
        }
        // Must track `populate_auipc`, which skips `auipc x0`.
        if matches!(event.instruction.opcode, Opcode::AUIPC) && event.instruction.op_a != 0 {
            add_events += 1;
        }

        (add_events, lt_events)
    }
}

impl<F: PrimeField32> CpuChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let mut new_alu_events = HashMap::new();

        // Populate chunk and clk columns.
        self.populate_chunk_clk(cols, event, blu_events);

        // Populate basic fields.
        cols.pc = Addr::try_from(event.pc).unwrap();
        cols.next_pc = Addr::try_from(event.next_pc).unwrap();

        // Range check pc limbs (3 limbs × 16 bits = 48 bits)
        let pc_limb0 = event.pc as u16;
        let pc_limb1 = (event.pc >> 16) as u16;
        let pc_limb2 = (event.pc >> 32) as u16;
        blu_events.add_u16_range_check(pc_limb0);
        blu_events.add_u16_range_check(pc_limb1);
        blu_events.add_u16_range_check(pc_limb2);

        // Range check next_pc limbs
        let next_pc_limb0 = event.next_pc as u16;
        let next_pc_limb1 = (event.next_pc >> 16) as u16;
        let next_pc_limb2 = (event.next_pc >> 32) as u16;
        blu_events.add_u16_range_check(next_pc_limb0);
        blu_events.add_u16_range_check(next_pc_limb1);
        blu_events.add_u16_range_check(next_pc_limb2);

        cols.instruction.populate(event.instruction);
        cols.opcode_selector.populate(event.instruction);

        *cols.op_a_access.value_mut() = Word::from(event.a);
        *cols.op_b_access.value_mut() = Word::from(event.b);
        *cols.op_c_access.value_mut() = Word::from(event.c);

        // Populate memory accesses for a, b, and c.
        if let Some(record) = event.a_record {
            cols.op_a_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, blu_events);
        }
        if let Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }

        // Pair the `slice_range_check_u16(&op_a_access.access.value.0, is_real)` the AIR
        // emits in `register/constraints.rs`. The AIR looks these limbs up on every real
        // row, so without the matching events here the byte table has no multiplicity to
        // answer with and even an honest trace fails on the regional cumulative sum.
        //
        // ⚠️ Must come **after** `op_a_access.populate` above, not before. `populate_access`
        // (`read_write/traces.rs`) does `self.value = current_record.value.into()`, and the
        // emulator zeroes writes to `x0` (`rw()`), while `event.a` keeps the computed result.
        // Reading the column first therefore requested `U16Range` on `event.a`'s limbs while the
        // AIR looked up four zeros -- a Byte-bus imbalance on every `rd == x0` instruction with a
        // non-zero result (`j`, `ret`, `auipc x0`, `add x0, ..`). Regression:
        // `x0_destination_with_nonzero_result`.
        for limb in cols.op_a_access.value().0.iter() {
            blu_events.add_u16_range_check(limb.as_canonical_u32() as u16);
        }

        // num_extra_clk is stored in the 3rd-byte of syscall code
        // which comes from the syscall's num_extra_cycles() return value.
        // For non-ecall instructions, this is 0.
        let num_extra_clk = if event.instruction.is_ecall_instruction() {
            let syscall_code = cols.op_a_access.prev_value().to_u64();
            F::from_canonical_u8(((syscall_code >> 16) & 0xFF) as u8)
        } else {
            F::ZERO
        };
        cols.num_extra_clk = num_extra_clk;

        self.populate_branch(cols, event, &mut new_alu_events);
        self.populate_jump(event, &mut new_alu_events, blu_events);
        self.populate_auipc(event, &mut new_alu_events);
        let is_halt = self.populate_ecall(cols, event, blu_events);

        cols.is_sequential_instr = F::from_bool(
            !event.instruction.is_branch_instruction()
                && !event.instruction.is_jump_instruction()
                && !is_halt,
        );

        // Populate carry columns for add_limb_with_carry constraints.
        // carry_a and carry_b store the carries for pc+4 = result limb-wise addition.
        // Both sequential and branch-not-taken use Addr carries (4 elements).
        // Jump uses Word carries (5 elements).
        let base: u64 = 1 << 16;
        let pc_limbs = [
            event.pc & 0xFFFF,
            (event.pc >> 16) & 0xFFFF,
            (event.pc >> 32) & 0xFFFF,
        ];
        let next_pc_limbs = [
            event.next_pc & 0xFFFF,
            (event.next_pc >> 16) & 0xFFFF,
            (event.next_pc >> 32) & 0xFFFF,
        ];

        // For sequential and branch-not-taken rows: carry_b = carries for pc+4=local.next_pc
        // Note: carry_a (for pc+4=next_row.pc) is computed in generate_main post-processing,
        // since it requires access to the next row's pc which isn't available here.
        if cols.is_sequential_instr == F::ONE || cols.not_branching == F::ONE {
            let mut carry: u64 = 0;
            for i in 0..4 {
                let lhs = if i < 3 { pc_limbs[i] } else { 0 };
                let rhs = if i < 3 { next_pc_limbs[i] } else { 0 };
                let inc = if i == 0 { 4u64 } else { 0 };
                carry = (carry + lhs + inc - rhs) / base;
                cols.pc_carry_b[i] = F::from_canonical_u64(carry);
            }
        }

        // For jump rows: carry_a = carries for pc+4=op_a (return address, Word 4 limbs)
        if event.instruction.is_jump_instruction() && event.instruction.op_a != 0 {
            let op_a = event.a;
            let op_a_limbs = [
                op_a & 0xFFFF,
                (op_a >> 16) & 0xFFFF,
                (op_a >> 32) & 0xFFFF,
                (op_a >> 48) & 0xFFFF,
            ];
            let mut carry: u64 = 0;
            for i in 0..5 {
                let lhs = if i < 3 { pc_limbs[i] } else { 0 }; // pc is Addr (3 limbs), 4th=0
                let rhs = if i < 4 { op_a_limbs[i] } else { 0 };
                let inc = if i == 0 { 4u64 } else { 0 };
                carry = (carry + lhs + inc - rhs) / base;
                cols.pc_carry_a[i] = F::from_canonical_u64(carry);
            }
        }

        // Assert that the instruction is not a no-op.
        cols.is_real = F::ONE;

        // Dispatch multiplicities, zero when the destination is `x0`.
        let not_x0 = F::from_bool(event.instruction.op_a != 0);
        cols.is_alu_not_x0 = F::from_bool(event.instruction.is_alu_instruction()) * not_x0;
        cols.is_auipc_not_x0 = F::from_bool(event.instruction.opcode == Opcode::AUIPC) * not_x0;

        // Bit 0 of the unmasked target, which the emulator masked out of `next_pc`.
        cols.jalr_lsb = if event.instruction.opcode == Opcode::JALR {
            F::from_canonical_u64(event.b.wrapping_add(event.c) & 1)
        } else {
            F::ZERO
        };

        new_alu_events
    }

    fn pad_to_power_of_two(&self, shape: Option<&RiscvPadShape>, values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if let Some(shape) = shape {
            1 << shape.inner[&self.name()]
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::ZERO);

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..].pico_iter_mut().for_each(|padded_row| {
            padded_row[CPU_COL_MAP.opcode_selector.imm_b] = F::ONE;
            padded_row[CPU_COL_MAP.opcode_selector.imm_c] = F::ONE;
        });
    }
}
