use super::{
    columns::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS},
    CpuChip,
};
use crate::{
    chips::chips::{
        alu::event::AluEvent,
        byte::event::ByteRecordBehavior,
        riscv_cpu::event::CpuEvent,
        riscv_memory::{event::MemoryRecordEnum, read_write::columns::MemoryLiteCols},
    },
    compiler::{
        addr::Pc,
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode},
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    iter::{IntoPicoRefMutIterator, PicoBridge, PicoIterator, PicoSlice},
    machine::chip::ChipBehavior,
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
        let n_real_rows = input.cpu_events.len();
        let mut values = vec![F::ZERO; n_real_rows * NUM_CPU_COLS];

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
                        self.event_to_row(
                            &input.cpu_events.as_slice()[idx],
                            cols,
                            &mut byte_lookup_events,
                        );
                        // The chain's sink: the AIR defines `is_last` as `is_real - next.is_real`
                        // (`eval_row_chain`), so exactly the last real row carries it, and the
                        // public-value hand-off reads it.
                        if idx + 1 == n_real_rows {
                            cols.is_last = F::ONE;
                        }
                    });
            });

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
            .as_slice()
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

impl<F: PrimeField32> CpuChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let mut new_alu_events = HashMap::new();

        // Populate the clk column.
        self.populate_chunk_clk(cols, event);

        // Populate basic fields. A pc is two limbs: `Pc::try_from` rejects anything at or above
        // 2^32, which the disassembler's guest address bound already rules out.
        cols.pc = Pc::try_from(event.pc).unwrap();
        cols.next_pc = Pc::try_from(event.next_pc).unwrap();

        // Neither pc nor next_pc emits range-check events any more: both lookups are gone on the
        // AIR side. pc's two limbs are pinned element by element to the preprocessed Program
        // table's canonical `Pc::try_from(pc_base + 4i)`, which is strictly stronger than a
        // range check; emitting byte events here would leave the Byte table with multiplicity no
        // lookup claims, and even an honest trace would fail the regional cumulative sum.

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

        // No byte event for a jump row's return address: the AIR has no range check on `op_a`
        // there. Limb 0 of `pc + 4` is canonical because `pc_carry` (below) is pinned to the
        // Program table's `[pc[0] >= 0xFFFC]` (`register/constraints.rs`).

        // num_extra_clk is stored in the 3rd-byte of syscall code
        // which comes from the syscall's num_extra_cycles() return value.
        // For non-ecall instructions, this is 0.
        let num_extra_clk = if event.instruction.is_ecall_instruction() {
            let syscall_code = cols.op_a_access.prev_value().to_u64();
            F::from_u8(((syscall_code >> 16) & 0xFF) as u8)
        } else {
            F::ZERO
        };
        cols.num_extra_clk = num_extra_clk;

        // The only ALU event a Cpu row synthesizes is the branch comparison. A JALR target is
        // proven in-chip (`jump/constraints.rs`), so there is no `populate_jump`.
        self.populate_branch(cols, event, &mut new_alu_events);

        // The syscall decode gadgets and their byte lookups moved to
        // the Ecall chip. The Cpu row only commits the halt flag, whose correctness on ecall
        // rows is certified by the Ecall-chip lookup.
        let is_halt = event.instruction.is_ecall_instruction()
            && (cols.op_a_access.prev_value().to_u64() & 0xFF) as u32
                == SyscallCode::HALT.syscall_id();
        cols.is_halt = F::from_bool(is_halt);

        // `pc_carry = [pc[0] >= 0xFFFC]` on every real row. The column travels in the Program
        // message, so it has to equal the preprocessed table's value for this pc
        // (`riscv_program/traces.rs` writes the same function of the row's pc). On a jump row
        // with `rd != x0` it is the carry out of limb 0 in `pc + 4 = op_a`
        // (`Pc::add_limb_with_carry`, `jump/constraints.rs`): a table pc is 4-aligned, so
        // `pc[0] + 4` overflows exactly when `pc[0] == 0xFFFC`. Only limb 0 can carry -- a guest
        // address stays below `0x7800_0000`, so limb 1 absorbs the carry without overflowing,
        // and `op_a`'s limb 2 is zero (a pc has none); the AIR checks those two as plain
        // equalities. Padding rows leave it at 0 (`pad_to_power_of_two`).
        cols.pc_carry = F::from_bool((event.pc & 0xFFFF) >= 0xFFFC);

        // Assert that the instruction is not a no-op.
        cols.is_real = F::ONE;

        // ALU dispatch multiplicity, zero when the destination is `x0`.
        let not_x0 = F::from_bool(event.instruction.op_a != 0);
        cols.is_alu_not_x0 = F::from_bool(event.instruction.is_alu_instruction()) * not_x0;

        // Bit 0 of the unmasked target, which the emulator masked out of `next_pc`.
        cols.jalr_lsb = if event.instruction.opcode == Opcode::JALR {
            F::from_u64(event.b.wrapping_add(event.c) & 1)
        } else {
            F::ZERO
        };

        new_alu_events
    }

    fn pad_to_power_of_two(&self, shape: Option<&RiscvPadShape>, values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if let Some(shape) = shape {
            let padded = 1 << shape.inner[&self.name()];
            // `values.resize` below would otherwise silently TRUNCATE real rows.
            assert!(
                padded >= n_real_rows,
                "Cpu shape height {padded} < {n_real_rows} real rows (shape bucket too small)"
            );
            padded
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
